<?php
set_time_limit(1000);
$connection=mysql_connect('localhost','root','') or die(mysql_error());
$db=mysql_select_db('dictionary') or die(mysql_error());

//$handle=fopen('fulldictionary.txt','r') or die(mysql_error());
$meaning1='';

$q="select word from word_meaning";
$res=mysql_query($q) or die(mysql_error());

while($row=mysql_fetch_array($res))
{
extract($row);
$word=strtolower($word);

//echo"<form action='http://en.wiktionary.org/wiki/srttolower($word)' method='get'>";
$handle=fopen('http:en.wiktionary.org/wiki/$word','r');

$word1='';
while(!feof($handle))
{
$word1.=fgets($handle);
}

$q1="update word_meaning set(word='$word', meaning='$word1') where word='$word' ";
mysql_query($q1) or die(mysql_error());
}
?>