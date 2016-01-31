<?php
set_time_limit(30000);
$connection=mysql_connect('localhost', 'root','') or die(mysql_error());
$db=mysql_select_db('dictionary') or die(mysql_error());

$handle=fopen('database_dictionary.txt','r');
$c=1;
$w='';
$meaning1='';
$word1='';
while(!feof($handle))
{
$w=fgets($handle);
$m=preg_match("/[A-Z]+[\-\;]*[A-Z]+(\s)+/", $w,$match_word);
//$m=preg_match("/[A-Z]+[\'\-\;]?[A-Z]+[\'\-\;]?\s*/", $w,$match_word);
if($m!=0)
{
$q="insert into word values('$w','')";
mysql_query($q) or die(mysql_error());
$word1=$w;
//$word1[$c]=$match_word[0];
$c++;
$meaning1='';}
else
{
$meaning1.=$w;
$q="update word set meaning='$meaning1' where word='$word1'";
mysql_query($q) or die(mysql_error());
//$meaning1[$c-1].=$w;
}

}
print_r($word);
/*

for($i=1;$i<=$c;$i++){
$d=$word[$i];
$m=$meaning[$i];
//$q="insert into word values('$d','$m')";
//mysql_query($q) or die(mysql_error());
}

*/
fclose($handle);

?>