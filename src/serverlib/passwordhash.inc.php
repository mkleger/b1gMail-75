<?php
/*
 * b1gMail password hashing policy (user + admin)
 */

/**
 * @return void
 */
function PasswordHashApplyPrefDefaults()
{
	global $bm_prefs;

	if(!isset($bm_prefs['pw_hash_li_algo']) || !PasswordHashAlgoIsValid($bm_prefs['pw_hash_li_algo']))
		$bm_prefs['pw_hash_li_algo'] = 'bcrypt';
	if(!isset($bm_prefs['pw_hash_admin_algo']) || !PasswordHashAlgoIsValid($bm_prefs['pw_hash_admin_algo']))
		$bm_prefs['pw_hash_admin_algo'] = 'bcrypt';

	$bm_prefs['pw_hash_li_cost'] = PasswordHashNormalizeCost(
		isset($bm_prefs['pw_hash_li_cost']) ? $bm_prefs['pw_hash_li_cost'] : 12,
		$bm_prefs['pw_hash_li_algo']);
	$bm_prefs['pw_hash_admin_cost'] = PasswordHashNormalizeCost(
		isset($bm_prefs['pw_hash_admin_cost']) ? $bm_prefs['pw_hash_admin_cost'] : 12,
		$bm_prefs['pw_hash_admin_algo']);
}

/**
 * @param string $algo
 * @return bool
 */
function PasswordHashAlgoIsValid($algo)
{
	return $algo === 'bcrypt' || $algo === 'argon2id';
}

/**
 * @return bool
 */
function PasswordHashArgon2Available()
{
	return defined('PASSWORD_ARGON2ID');
}

/**
 * @param string $context 'li' or 'admin'
 * @return string bcrypt|argon2id
 */
function PasswordHashPrefAlgo($context)
{
	global $bm_prefs;

	$key = ($context === 'admin') ? 'pw_hash_admin_algo' : 'pw_hash_li_algo';
	$algo = isset($bm_prefs[$key]) ? $bm_prefs[$key] : 'bcrypt';

	if($algo === 'argon2id' && !PasswordHashArgon2Available())
		return 'bcrypt';

	if(!PasswordHashAlgoIsValid($algo))
		return 'bcrypt';

	return $algo;
}

/**
 * @param string $context
 * @return int
 */
function PasswordHashPrefCost($context)
{
	global $bm_prefs;

	$key = ($context === 'admin') ? 'pw_hash_admin_cost' : 'pw_hash_li_cost';
	$algo = PasswordHashPrefAlgo($context);

	return PasswordHashNormalizeCost(isset($bm_prefs[$key]) ? $bm_prefs[$key] : 12, $algo);
}

/**
 * @param int|string $cost
 * @param string     $algo
 * @return int
 */
function PasswordHashNormalizeCost($cost, $algo)
{
	$cost = (int)$cost;

	if($algo === 'argon2id')
		return max(2, min(6, $cost > 0 ? $cost : 4));

	return max(10, min(15, $cost > 0 ? $cost : 12));
}

/**
 * @param string $context li|admin
 * @return array{algo:int,options:array}
 */
function PasswordHashParams($context)
{
	$algoName = PasswordHashPrefAlgo($context);
	$cost = PasswordHashPrefCost($context);

	if($algoName === 'argon2id')
	{
		return array(
			'algo'    => PASSWORD_ARGON2ID,
			'options' => array(
				'memory_cost' => 65536,
				'time_cost'   => $cost,
				'threads'     => 1,
			),
		);
	}

	return array(
		'algo'    => PASSWORD_BCRYPT,
		'options' => array('cost' => $cost),
	);
}

/**
 * @param string $plain
 * @param string $context li|admin
 * @return string
 */
function PasswordHashCreate($plain, $context = 'li')
{
	$params = PasswordHashParams($context);

	return password_hash((string)$plain, $params['algo'], $params['options']);
}

/**
 * @param string $hash
 * @return bool
 */
function PasswordHashIsModern($hash)
{
	return is_string($hash) && strlen($hash) >= 4 && $hash[0] === '$';
}

/**
 * @param string $hash
 * @param string $context li|admin
 * @return bool
 */
function PasswordHashNeedsUpgrade($hash, $context = 'li')
{
	if(!PasswordHashIsModern($hash))
		return true;

	$params = PasswordHashParams($context);

	return password_needs_rehash($hash, $params['algo'], $params['options']);
}

/**
 * Maximum characters the password column can store (0 = unknown).
 *
 * @param string $table
 * @param string $column
 * @return int
 */
function PasswordHashColumnMaxLength($table, $column)
{
	global $db;

	static $cache = array();
	$key = $table . '.' . $column;
	if(isset($cache[$key]))
		return $cache[$key];

	$res = $db->Query('SHOW COLUMNS FROM {pre}' . $table . ' LIKE ?', $column);
	$col = $res->FetchArray(MYSQLI_ASSOC);
	$res->Free();
	if(!is_array($col) || empty($col['Type']))
		return $cache[$key] = 0;

	$type = strtolower((string)$col['Type']);
	if(preg_match('/^(?:var)?char\((\d+)\)/', $type, $m))
		return $cache[$key] = (int)$m[1];
	if(strpos($type, 'text') !== false || strpos($type, 'blob') !== false)
		return $cache[$key] = PHP_INT_MAX;

	return $cache[$key] = 0;
}

/**
 * @param string $table
 * @param string $column
 * @param string $hash
 * @return bool
 */
function PasswordHashCanStoreInColumn($table, $column, $hash)
{
	$max = PasswordHashColumnMaxLength($table, $column);
	if($max <= 0)
		return true;

	return strlen((string)$hash) <= $max;
}

/**
 * @param string      $table
 * @param string      $idColumn
 * @param int         $id
 * @param string      $hashColumn
 * @param string      $saltColumn
 * @param string      $newHash
 * @param string      $oldHash
 * @param string|null $oldSalt
 * @return bool
 */
function PasswordHashWriteAndVerify($table, $idColumn, $id, $hashColumn, $saltColumn, $newHash, $oldHash, $oldSalt)
{
	global $db;

	$id = (int)$id;
	if($id <= 0 || !is_string($newHash) || $newHash === '')
		return false;

	if(!PasswordHashCanStoreInColumn($table, $hashColumn, $newHash))
		return false;

	$db->Query('UPDATE {pre}'.$table.' SET `'.$hashColumn.'`=?,`'.$saltColumn.'`=? WHERE `'.$idColumn.'`=?',
		$newHash,
		'',
		$id);

	$res = $db->Query('SELECT `'.$hashColumn.'` FROM {pre}'.$table.' WHERE `'.$idColumn.'`=?', $id);
	$row = $res->FetchArray(MYSQLI_ASSOC);
	$res->Free();

	if(!is_array($row) || !hash_equals($newHash, (string)$row[$hashColumn]))
	{
		$db->Query('UPDATE {pre}'.$table.' SET `'.$hashColumn.'`=?,`'.$saltColumn.'`=? WHERE `'.$idColumn.'`=?',
			$oldHash,
			$oldSalt,
			$id);
		return false;
	}

	return true;
}

function PasswordHashUpgradeUser($userID, $passwordPlain, $row)
{
	if(!is_array($row) || !isset($row['passwort']))
		return;

	if(!PasswordHashNeedsUpgrade($row['passwort'], 'li'))
		return;

	$passwordPlain = CharsetDecode($passwordPlain, false, 'ISO-8859-15');
	$newHash = PasswordHashCreate($passwordPlain, 'li');
	$oldSalt = isset($row['passwort_salt']) ? $row['passwort_salt'] : '';

	if(!PasswordHashWriteAndVerify('users', 'id', $userID, 'passwort', 'passwort_salt', $newHash, $row['passwort'], $oldSalt))
		return;

	if(function_exists('ClientApiRememberPassword'))
		ClientApiRememberPassword((int)$userID, $passwordPlain);
}

/**
 * @param int    $adminID
 * @param string $passwordPlain
 * @param string $currentHash
 * @param string $currentSalt
 * @return string|false New hash or false if unchanged / not stored
 */
function PasswordHashUpgradeAdmin($adminID, $passwordPlain, $currentHash, $currentSalt = '')
{
	if(!PasswordHashNeedsUpgrade($currentHash, 'admin'))
		return false;

	$newHash = PasswordHashCreate($passwordPlain, 'admin');
	if(!PasswordHashWriteAndVerify('admins', 'adminid', $adminID, 'password', 'password_salt', $newHash, $currentHash, $currentSalt))
		return false;

	return $newHash;
}

/**
 * @param int    $userID
 * @param string $passwordPlain
 * @return void
 */
function PasswordHashSetUserPassword($userID, $passwordPlain)
{
	global $db;

	$passwordPlain = CharsetDecode($passwordPlain, false, 'ISO-8859-15');
	$newHash = PasswordHashCreate($passwordPlain, 'li');
	$oldHash = '';
	$oldSalt = '';

	$res = $db->Query('SELECT passwort,passwort_salt FROM {pre}users WHERE id=?', (int)$userID);
	if($res->RowCount() == 1)
	{
		$row = $res->FetchArray(MYSQLI_ASSOC);
		$oldHash = $row['passwort'];
		$oldSalt = $row['passwort_salt'];
	}
	$res->Free();

	if(!PasswordHashWriteAndVerify('users', 'id', $userID, 'passwort', 'passwort_salt', $newHash, $oldHash, $oldSalt))
		return;

	if(function_exists('ClientApiRememberPassword'))
		ClientApiRememberPassword((int)$userID, $passwordPlain);
}

/**
 * @param int    $adminID
 * @param string $passwordPlain
 * @return string|false
 */
function PasswordHashSetAdminPassword($adminID, $passwordPlain)
{
	global $db;

	$newHash = PasswordHashCreate($passwordPlain, 'admin');
	$oldHash = '';
	$oldSalt = '';

	$res = $db->Query('SELECT `password`,`password_salt` FROM {pre}admins WHERE `adminid`=?', (int)$adminID);
	if($res->RowCount() == 1)
	{
		$row = $res->FetchArray(MYSQLI_ASSOC);
		$oldHash = $row['password'];
		$oldSalt = $row['password_salt'];
	}
	$res->Free();

	if(!PasswordHashWriteAndVerify('admins', 'adminid', $adminID, 'password', 'password_salt', $newHash, $oldHash, $oldSalt))
		return false;

	return $newHash;
}

/**
 * @return array
 */
function PasswordHashAdminAlgoChoices()
{
	$choices = array('bcrypt' => 'bcrypt');
	if(PasswordHashArgon2Available())
		$choices['argon2id'] = 'Argon2id';

	return $choices;
}

