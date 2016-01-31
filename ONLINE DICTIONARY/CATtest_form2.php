<?php 
           
           session_start();
//            echo "session 1";
           $_SESSION['session_id']=$_POST['username'];
           $_SESSION['session_level']=$_POST['difficulty'];
           $_SESSION['session_exam_type']=$_POST['exam'];
		  $_SESSION['score']=0;
		   if($_POST['difficulty']=='easy')
		   $_SESSION['session_ques_no']=1;
		   else if($_POST['difficulty']=='medium')
		   $_SESSION['session_ques_no']=4;
		   else if($_POST['difficulty']=='hard')
		   $_SESSION['session_ques_no']=7;
//echo "see the session data...";
//print_r($_SESSION);

echo "welcome ".$_SESSION['session_id']." !!!!";
//echo "<form action='CATtest.php' method='post'>";
echo "<form action='word_builder_test.php' method='post'>";
echo "<input type='submit' value='proceed_ session stored!' />";
echo"</form>";   
 
           ?>
     