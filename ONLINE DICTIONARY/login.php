<?php
$connection=mysql_connect('localhost','root','') or die(mysql_erreor());
mysql_select_db('dictionary') or die(mysql_error());

$u=$_POST['username'];
$p=$_POST['password'];

$q="select username, password from user where username='$u' ";
$res=mysql_query($q) or die(mysql_error());

while($rows=mysql_fetch_array($res))
{
extract($rows);

if($u==$username && $p==$password)
{
//echo "password validated! ";
echo "<form action='login_page.html' method='post'>";
echo "<input type='submit' name='submit' value='proceed further...'>";
echo"</form>";
}

else
{
echo "<form action='home.html' method='post'>";
echo "<input type='submit' name='submit' value='go back...to login!'>";
echo"</form>";
}
}

?>