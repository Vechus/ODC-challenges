# Serialize

1. register a user
2. login with the user
3. let's look at upload_user.php:
    line 27, unserialize($data), where data is uploaded by the user. Interesting.
4. let's look at data.php:
    line 31: $f = fopen("./items/".$fid, "r");
    that means that if I create an Item and append it to the user, when unserializing it, it will print me the content of any item associated to the user
5. see attached script: save.php:
    after serializing and creating a file with the serialized user, uploading it will do the trick
    `php save.php`
6. upload the user
7. visit index.php: it should print the flag.
