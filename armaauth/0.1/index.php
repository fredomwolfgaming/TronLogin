<?php 

////////////////////////////////////////////////////
//
// Authentication server, reference implementation 0.1
// 
// To run authority X(siteDomain.TopLevelDomain), this script needs to be 
// adapted and be callable from a web browser as 
// http://X/armaauth/0.1
//
// the easiest way to do so is to name the script index.php
// and place it into an appropriate armaauth/0.1 
// directory on a web server that supports php.
//
//can also be placed in subfolders, so placing the script root in the website root's subfolder lolz of http:fredomwolf.tv
//would be logged in using username@fredomwolf.tv/lolz
//and the script would be located in the folder: PUBLIC_HTML/lolz/armaauth/0.1
////////////////////////////////////////////////////
function substitutions( $fix, $user )
{
    return str_replace( "%u", $user, $fix );
}
function conclude($statusCode, $msg)
{ 
    $statusCode = 200;
    header("Status: $statusCode", true, $statusCode); 
    header("Content-Type: text/plain");
    die("$msg\n"); 
} 
$authority = $_SERVER['HTTP_HOST'];
function getPassword( $user )
{
    //////////////////////////////////////////////
    //----------USERNAME PLAINTEXT DATABASE-------
    //////////////////////////////////////////////

    ////////////////////////////////////////////////////
    //REGULAR USER DATABASE STYLE
    // user => 'password'
    // insert comma after every entry except the last
    //spaces dont count
    //EXAMPLE
    //
    //$passwords= array (
    //  firstuser => 'The_Water',
    //  lastuser => 'HaHa'
    //  );
    //
    ///////////////////////////////////////////////////

    ////////////////////////////////
    //FAKE USERNAME STYLE
    //match to any username, but need specific password to get a SUCCESS username/password section response.
    //actctual message sent to the server can be set in the return alteration area at the bottom.
    //a failed login, can go to the match failed section, but still send a regular success response.
    //or a failed login can modify the username but still succeed, while a successful match can send the unmodified username
    //you could even use a database style and upon failed match, send a modified success response.
    $passwords= array (
        //match any usename, the master password is fake
       $user => 'fake' 
       );
    ////////////////////////////////////

    //////////////////////////////////////////////////////////////
    //end of username area, proceed to return modification section
    //////////////////////////////////////////////////////////////

    $password = $passwords[ $user ];
    if ( NULL == $password )
        return NULL;
    return array( $user, $password );
}
function getPrefix()
{
    return "%u:aaauth:";
}
function getSuffix()
{
    global $authority;
    return ":$authority";
}
function getPasswordHash( $user, $method )
{
    $userInfo = getPassword( $user );
    if ( NULL == $userInfo )
        return NULL;

    $trueUser = $userInfo[0];
    $password = $userInfo[1];
    if ( $trueUser != $user && ( strpos( getPrefix(), '%u' ) !== FALSE || strpos( getPrefix(), '%u' ) !== FALSE ) )
    {
        conclude(404, 'UNKNOWN_USER ' . $user . ' Do not use %u in pre/suffix if your user database is making case-insensitive lookups.');
    }
    switch( $method )
    {
    case 'bmd5':
        $password = "$password" . chr(0); 
        break;

    case "md5":
        $password =  substitutions( getPrefix(), $trueUser ) . "$password" . substitutions( getSuffix(), $trueUser );
        break;
    }
    return array( $trueUser, md5( $password ) );
}
function getMethods()
{
    return "md5, bmd5";
}
$query = @strtolower($_REQUEST['query'] . '');
switch ( $query )
{
case "methods":
    conclude(200, 'METHODS '. getMethods() );
    break;
case "params":
    $method = @strtolower($_REQUEST['method'] . ''); 
    if ( $method == 'md5' )
    {
        conclude( 200, "PREFIX " . getPrefix() . "\nSUFFIX " . getSuffix() );
    }
    if ( $method == 'bmd5' )
    {
        conclude(200 , '' );
    }
    conclude(404 , 'UNKNOWN_METHOD' );
    break;
case "check":
    $method = @strtolower($_REQUEST['method'] . ''); 
    $user = @$_REQUEST['user'] . ''; 
    $salt = @$_REQUEST['salt'] . ''; 
    $hash = @$_REQUEST['hash'] . ''; 
    $userInfo = getPasswordHash( $user, $method );
    if ( $userInfo == NULL )
    {
        conclude(404, 'UNKNOWN_USER ' . $user );
    }
    $trueUser            = $userInfo[0];
    $correctPasswordHash = $userInfo[1];
    $packedSalt                = pack("H*", $salt); 
    $correctPackedPasswordHash = pack('H*', $correctPasswordHash); 
    $correctHash = md5($correctPackedPasswordHash . $packedSalt); 
    if (strcasecmp($hash, $correctHash) === 0)
    /////////////////////////////////////////////
    //---------RETURN ALTERATION AREA -----------
    /////////////////////////////////////////////

    //to indicate a failed login, use:
    //conclude(200, 'PASSWORD_fAIL ' . '@' . $authority . "\nFOO baz" ); 

    //to allow login, but alter the username portion use this type of modification: 
    //(you don't have to have something on both sides of the username. the . 'thingHere'. is to append to the username string)
    //conclude(200, 'PASSWORD_OK ' . '$~' . $trueUser . '~$@' . $authority . "\nFOO baz" );

    //to add subdirectory onto the username's authority, when the login script is located in the root directory:
    //conclude(200, 'PASSWORD_OK ' . $trueUser . '@' . $authority . "/fake" . "\nFOO baz" ); 

    //you canm modify the subdirectories, but leave the base authority part alone.
    //conclude(200, 'PASSWORD_OK ' . $trueUser . '@' . $authority . "/fake/lol/i/am/lost" . "\nFOO baz" ); 

    {//-----on success, send this----
        conclude(200, 'PASSWORD_OK ' . $trueUser . '@' . $authority . "/fake" . "\nFOO baz" ); 
    }

    //-----on failed username/password match, send this ----
    conclude(200, 'PASSWORD_OK ' . $trueUser . '@' . $authority . "/fake/unreal" . "\nFOO baz" ); 

    ////////////////////////////////////////////////
    //---------end of auth return alterations-------
    ////////////////////////////////////////////////
    break;
default:
    conclude(404, 'UNKNOWN_QUERY');
}
?>
