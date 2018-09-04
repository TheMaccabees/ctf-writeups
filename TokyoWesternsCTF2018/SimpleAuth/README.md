# SimpleAuth

In this challange we were first displayed with the following url: ```simpleauth.chal.ctf.westerns.tokyo```

After browsing to the above url we are given the following php code:
```php
<?php

require_once 'flag.php';

if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['action'])){
        $action = $res['action'];
    }
}

if ($action === 'auth') {
    if (!empty($res['user'])) {
        $user = $res['user'];
    }
    if (!empty($res['pass'])) {
        $pass = $res['pass'];
    }

    if (!empty($user) && !empty($pass)) {
        $hashed_password = hash('md5', $user.$pass);
    }
    if (!empty($hashed_password) && $hashed_password === 'c019f6e5cd8aa0bbbcc6e994a54c757e') {
        echo $flag;
    }
    else {
        echo 'fail :(';
    }
}
else {
    highlight_file(__FILE__);
}
```

## Code Flow
* First the code checks if we have given it a query string i.e. ```simpleauth.chal.ctf.westerns.tokyo/?<query string>```
    * if our query string is not empty then the we enter the block, our query string is parsed and set to the variable ```$res```
    * if the ```'key'``` action exists within our query string and it isn't empty then the ```$action``` variable is set to the value associated with ```'key'```
* Now we approach the second but larger if statment. Here the program checks if our previously set ```$action``` variable is equal to ```'auth'``` meaning to enter this block we need our url to look something like this: ```simpleauth.chal.ctf.westerns.tokyo/?action=auth```
    * assuming we enter this block we have four checks:
        1. ```$res['user']``` isn't empty, if it isn't then ```$user``` is set to its value
        2. ```$res['pass']``` isn't empty, if it isn't then ```$pass``` is set to its value
        3. ```$user``` and ```$password``` are not empty, if they aren't then ```$hashed_password``` is set to the md5 of the concatenated ```$user``` and ```$pass``` variables
        4. the final check is to see that ```$hashed_password``` is set and equal to the following md5 value ```c019f6e5cd8aa0bbbcc6e994a54c757e```, **if the forth check passes we get the flag**

## Vulnerable Functions
Now that we understand the flow of the program let's look at some standout functions & operations to see if any have known security warnings,
scanning the code from top to bottom we can create the following table:

|Function Name | Documentation Page | Security Warning
|--------------|--------------------|-----------------
|```empty```|http://php.net/manual/en/function.empty.php|no
|```parse_str```|http://php.net/manual/en/function.parse-str.php|yes
|```md5```|urlhttp://php.net/manual/en/function.md5.php|yes

Great now we have  some leades:
## ```md5```
md5 has the following warning: ```It is not recommended to use this function to secure passwords, due to the fast nature of this hashing algorithm...```
this however is well known and considering that this isn't a crypto challenge we probably are not needed to attempt to bruteforce this hash...

## ```parse_str```
On the ```parse_str``` page we see the following warning in red

    Warning
    Using this function without the result parameter is highly DISCOURAGED and DEPRECATED as of PHP 7.2.

    Dynamically setting variables in function's scope suffers from exactly same problems as register_globals.

    Read section on security of Using Register Globals explaining why it is dangerous.

Interesting! What is the "result parameter"? We see that ```parse_str``` is defined as so:

```void parse_str ( string $encoded_string [, array &$result ] )```

We can see that the ```&$result``` parameter (mentiononed in  the warning) is optional we know that the warning applies to the use of ```parse_str``` without said result parameter. Looking back at the given code we see that it uses ```parse_str``` with only 1 parameter so it is indeed vulnerable to the vulnerability described in the warning above!

This means that if our url looks like this:
```simpleauth.chal.ctf.westerns.tokyo/?action=auth&one=1```
then we will be defining a variable ```$one``` and its value will be ```1```. Awesome!

Looking back at the interesting part of the code:
```php
...
if ($action === 'auth') {
    ...
    if (!empty($hashed_password) && $hashed_password === 'c019f6e5cd8aa0bbbcc6e994a54c757e') {
        echo $flag;
    }
    ...
}
```
We can see that the only interesting checks are ```$action === 'auth'``` and ```!empty($hashed_password) && ...``` and we know that we can set ```$hashed_password``` arbitrarily using our query string

## Developing The Exploit
Now with the use of the vulnerable ```parse_str``` and knowing the flow we need to take to print our flag the following url when sent:

```http://ssimpleauth.chal.ctf.westerns.tokyo/?action=auth&hashed_password=c019f6e5cd8aa0bbbcc6e994a54c757e```

will result with:

```TWCTF{d0_n0t_use_parse_str_without_result_param}```