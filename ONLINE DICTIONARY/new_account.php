<?php
$connection=mysql_connect('localhost','root','') or die(mysql_erreor());
mysql_select_db('dictionary') or die(mysql_error());
echo "<center>";
echo "<form action='#' method='post'>";
echo "<table border='2'>";
echo"<tr><td>USERNAME</td><td><input type='text' name='username' size='40'></td></tr>";
echo"<tr><td>PASSWORD</td><td><input type='password' name='password' size='40'></td></tr>";
echo"<tr><td>FIRST NAME</td><td><input type='text' name='firstname' size='40'></td></tr>";
echo"<tr><td>MIDDLE NAME</td><td><input type='text' name='midname' size='40'></td></tr>";
echo"<tr><td>LAST NAME</td><td><input type='text' name='lastname' size='40'></td></tr>";
echo"<tr><td>AGE</td><td><input type='text' name='age' size='40'></td></tr>";
echo"<tr><td>GENDER</td><td><input type='radio'  name='gender'  value='m'/>MALE<br><input type='radio'  name='gender'  value='f'/>FEMALE</td></tr>";
echo"<tr><td>SECURITY QUESTION</td><td><select name='question' size='3'>
                                    <option>what was the name of your favorite car?</option>
                                    <option>what was the name of your favorite book?</option>
                                    <option>what was the name of your favorite fruit?</option>
                                    <option>what was the name of your favorite song?</option>
                                    <option>what was the name of your first best friend?</option>
                                    </select></td></tr>";
echo"<tr><td>ANSWER</td><td><input type='text' name='answer' size='40'></td></tr>";
echo"<tr><td>EMAIL ID</td><td><input type='text' name='email_id' size='40'></td></tr>";
echo"<tr><td colspan='2'><right><input type='submit' name='submit' value='submit your form' ></right></td></tr>";
echo "</table>";
echo "</form>";
echo "</center>";

$u=$_POST['username'];
$p=$_POST['password'];
$f=$_POST['firstname'];
$m=$_POST['midname'];
$l=$_POST['lastname'];
$a=$_POST['age'];
$g=$_POST['gender'];
$s=$_POST['question'];
$ans=$_POST['answer'];
$e=$_POST['email_id'];

$q="insert into user values('$u','$p','$f','$m','$l','$a','$g','$s','$ans','$e') ";
$res=mysql_query($q) or die(mysql_error());

echo "<br>details for user: $u  entered successfully!  <br>";
echo "<form action='login_page.html' method='post'>";
echo "<input type='submit' name='submit' value='proceed further...'>";
echo"</form>";

?>