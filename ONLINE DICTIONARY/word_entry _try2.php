<?php
set_time_limit(30000);
$connection=mysql_connect('localhost', 'root','') or die(mysql_error());
$db=mysql_select_db('dictionary') or die(mysql_error());

//$q="create table word_list(word varchar(20), meaning varchar(1000))";
//mysql_query($q) or die(mysql_error());

// for putting the dictionary words into the database

$str='';

//$handle=fopen('database_dictionary.txt','r');

$handle=fopen('database_dictionary.txt','r');
while(!feof($handle))
{

if(fgetc($handle)=='\n')
{
$str.='\n';
}
else

$str.=fgets($handle);

}
$str1=$str;
//$match_word=preg_split("/[A-Z]{2,}(\s)+/",$str1);

/*$match_word=preg_split("/[A-Z\-\']+[A-Z]+(\s)+/",$str1);
for($i=0;$i<count($match_word);$i++)
{
echo "<br>@[$i]@".$match_word[$i]."<br>";
}
*/

$match1=preg_split("/\s[A-Z]+(\s)+/",$str);

//print_r($match);

/*
for($i=0;$i<=count($match);$i++)
{
echo "<br>@[$i]@".$match[$i]."<br>@";
}
*/

//print_r($str);

$MATCHES=preg_match_all("/[A-Z\-\']+[A-Z]+(\s)+/",$str,$match);
print_r($MATCHES);
//print_r($match);
//$length = strlen($match);
/*
echo"<br /><br />";
for($i=0;$i<=$MATCHES;$i++)
{
echo "<br>[$i].".print_r($match[$i]." <br />";
}
*/
for($i=0;$i<$MATCHES;$i++){
$c=$match[0][$i];
$m=$match1[$i];
$q="insert into word values('$c','$m')";
mysql_query($q) or die(mysql_error());
}


fclose($handle);

?>