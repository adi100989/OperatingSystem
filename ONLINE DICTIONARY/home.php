<html>
<head>
<link href="act9_css.css" type="text/css" rel="stylesheet" />
<style type="text/css">
#clock { font-family: Arial, Helvetica, sans-serif; font-size: 0.8em; color: white; background-color: black; border: 2px solid purple; padding: 4px; }

div.scroll {
height: 120px;
width: 800px;
overflow: auto;
border: 1px solid #666;
background-color: #ccc;
padding: 0px;
}
</style>

<script type="text/javascript">
<!--

function init ( )
{
  timeDisplay = document.createTextNode ( "" );
  document.getElementById("clock").appendChild ( timeDisplay );
}

function updateClock ( )
{
  var currentTime = new Date ( );

  var currentHours = currentTime.getHours ( );
  var currentMinutes = currentTime.getMinutes ( );
  var currentSeconds = currentTime.getSeconds ( );

  // Pad the minutes and seconds with leading zeros, if required
  currentMinutes = ( currentMinutes < 10 ? "0" : "" ) + currentMinutes;
  currentSeconds = ( currentSeconds < 10 ? "0" : "" ) + currentSeconds;

  // Choose either "AM" or "PM" as appropriate
  var timeOfDay = ( currentHours < 12 ) ? "AM" : "PM";

  // Convert the hours component to 12-hour format if needed
  currentHours = ( currentHours > 12 ) ? currentHours - 12 : currentHours;

  // Convert an hours component of "0" to "12"
  currentHours = ( currentHours == 0 ) ? 12 : currentHours;

  // Compose the string for display
  var currentTimeString = currentHours + ":" + currentMinutes + ":" + currentSeconds + " " + timeOfDay;

  // Update the time display
  document.getElementById("clock").firstChild.nodeValue = currentTimeString;
}

// -->
</script>
</head>
<body onload="updateClock(); setInterval('updateClock()', 1000 )">

<div id="container">
<div id="lefthead">
<img src="extra/law-dictionary-roger.jpg" style="width:200px; height:120px"/>
</div>

  <div id="header">
    <b><h1>The Online Dictionary</h1>
   <h2> OnlineDictionary.com </h2> </b>
  </div>

<div id="rightheadtop">
<div style="width: 10em; text-align:center; margin: 20px auto;">
  <span id="clock">&nbsp;</span></div> 
</div>
<div id="rightheaddown">
<br /><form action="http://www.google.com/search.aspx" method="get" name="frmsearch">
<input type="text" value="" size="30px" name="searchbox" >
<center><input type="submit" value="search this site" name="search" /></center></form>
</div>
          <div id="menu">
<ul><center>  
  <li><a href="home.html">HOME</a>
    <ul>
      <li><a href="about_us.html">ABOUT US</a></li>
      <li><a href="contact.html">Contact Us</a></li>
      <li><a href="user_manual.html">User Manual</a></li>
    </ul>
    </li>


  <li><a href="#nogo">FACILITIES</a>
    <ul>
      <li><a href="dictionary.html">Browse The Dictionary</a></li>
      <li><a href="thesaurus.html">Thesaurus</a></li>
    </ul>
    </li>



  <li><a href="#nogo">TEST</a>
    <ul>
      <li><a href="sat.html">SAT</a></li>
      <li><a href="toefl">TOEFL</a></li>
      <li><a href="mba.html">MBA</a></li>
    </ul>
    </li>

<li><a href="#nogo">REFERENCES</a>
<ul>
<li><a href="database.html">Database source</a></li>
<li><a href="Word_builder.html">Word Builder Sources</a></li>

</ul>
</li>
<li><a href="#nogo">LINK</a>
<ul>
<li><a href="wordoftheday.html">Word Of The Day</a></li>
</ul>
</li></center>  
</ul> 
</div>
      
  <div id="leftBar">
<table name="lefttable" border="2" height="380px" width="269px" cellpadding="3"  >
<tr><td> <b><u>QUOTE OF THE DAY </u></b>
<BR />
My philosophy is that not only are you responsible for your life, but doing the best at this moment puts you in the best place for the next moment.
        Oprah Winfrey (1954 - )</td>
</tr>
   
<tr><td><u><b> WORD OF THE DAY</b></u><br />
equipoise
<br />


1. equality in distribution of weight, balance, or force; equilibrium: "They spent more than ten minutes shuffling items between their grocery bags to ensure equipoise for the long walk home."
<br />
2. an offsetting force or weight; counterpoise</td>
</tr>

<tr><td> <script LANGUAGE="javascript">
var mydate=new Date()
var year=mydate.getYear()
if (year < 1000)
year+=1900
var day=mydate.getDay()
var month=mydate.getMonth()
var daym=mydate.getDate()
if (daym<10)
daym="0"+daym
var dayarray=new Array("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday")
var montharray=new Array("January","February","March","April","May","June","July","August","September","October","November","December")
document.write("<small><font color='000000' face='Arial'><b>"+dayarray[day]+", "+montharray[month]+" "+daym+", "+year+"</b></font></small>")

</script><br /> <br /></td>
</tr>
</table>

  
</div>


  <div id="content">

    <table name="contenttable" height="380" width="800" border="1" margin="0" cellpadding="0" cellspacing="0">
     <tr><td><div class="scroll"> 
  <table name="inside_content" height="120" width="200" border="1" margin="0" cellpadding="0" cellspacing="0">
<tr> <td><a href="http://en.wikipedia.org/wiki/Wheel"><img src="extra/wheel.jpg" height="127" width="200"> </a> </td>
     <td><a href="http://en.wikipedia.org/wiki/Wheel"><img src="extra/Hipster.jpg" height="127" width="200"> </a> </td>
      <td><a href="http://en.wikipedia.org/wiki/Wheel"><img src="extra/Untitled02.jpg" height="127" width="200"> </a> </td>
       <td><a href="http://en.wikipedia.org/wiki/Wheel"><img src="extra/Independent-Study.jpg" height="127" width="200"> </a> </td>
 </tr></table> </div>
</td></tr>
     <tr><td><div class="scroll">
<PRE>A wheel is a device that allows heavy objects to be moved easily through rotating on an axle through its center, facilitating movement 
or transportation while supporting a load, or performing labor in machines. Common examples are found in transport applications. A wheel,
 together with an axle, overcomes friction by facilitating motion by rolling.
 In order for wheels to rotate, a moment needs to be applied to the wheel about its axis, either by way of gravity,
 or by application of another external force. More generally the term is also used for other circular objects that rotate or turn, such as a ship's
 wheel, steering wheel and flywheel.
<hr />        
                                Etymology

The English word wheel comes from the Old English word hweol, hweogol, from Proto-Germanic *hwehwlan, *hwegwlan, from Proto-Indo-European *kwekwlo-,[1]
 an extended form of the root *kwel- "to revolve, move around". Cognates within Indo-European include Greek ?????? kýklos, "wheel", Sanskrit chakra,
 Old Church Slavonic kolo, all meaning "circle" or "wheel",[2]

The Latin word rota is from the Proto-Indo-European *rota-, the extended o-grade form of the root *ret- meaning "to roll, revolve".[3]

Evidence of wheeled vehicles appears from the mid 4th millennium BC, near-simultaneously in Mesopotamia, the Northern Caucasus (Maykop culture) and Central
 Europe, so that the question of which culture originally invented the wheeled vehicle remains unresolved and under debate.

The earliest well-dated depiction of a wheeled vehicle (here a wagon—four wheels, two axles), is on the Bronocice pot, a ca. 3500–3350 BC clay pot excavated
 in a Funnelbeaker culture settlement in southern Poland.[4]

The wheeled vehicle spread from the area of its first occurrence (Mesopotamia, Caucasus, Balkans, Central Europe) across Eurasia, 
reaching the Indus Valley by the 3rd millennium BC. During the 2nd millennium BC, the spoke-wheeled chariot spread at an increased pace, 
reaching both China and Scandinavia by 1200 BC. In China, the wheel was certainly present with the adoption of the chariot in ca. 
1200 BC,[5] although Barbieri-Low[6] argues for earlier Chinese wheeled vehicles, circa 2000 BC.

</PRE>    
 <tr><td> <div class="scroll"><h2><center> NEWS</center> </h2>
<hr /><h3>Israel embassy car blast: Police searching for an abandoned red bike, studying CCTV footage </h3>
<center><a href="http://www.ndtv.com/article/india/israel-embassy-car-blast-police-searching-for-an-abandoned-red-bike-studying-cctv-footage-176031?pfrom=home-lateststories" target="http://www.ndtv.com/article/india/israel-embassy-car-blast-police-searching-for-an-abandoned-red-bike-studying-cctv-footage-176031?pfrom=home-lateststories">
<img src="extra/Israeli_car_burnt_295.jpg" width="300px" height="450px"></a> </center>
<br /> <center>CLICK THE IMAGE TO SEE THE WHOLE STORY. </center>
</div>
</td></tr>
    </table>
  </div>
  <div id="rightBar">
<b>
<CENTER><h2><u> LOGIN DETAILS</u></h2> </CENTER>
 
 <div id="newacc" style="text-align:center">
    <h4>Create a new account <a href="new_account.php" target="new_account.php"> here.</a></h4>
     </div>
     <form name="user" action=# method="POST">  
  
             USERNAME: <input type="text" name="username" value="" size="30" /> <BR />
      
           PASSWORD:  <input type="password" name="password" value="" size="30" /> <br />
            
         <input type="submit" value="submit" name="submit" />  
       
        </form>
		
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
 <center>Forgot Your Password? <a href="passrecover.html" target="passrecover.html">( click here )</a></center>
 </b> </div>
  <div id="footer" style="text-align:center">
<br />
<div id="br">    <h1>Browse The Web...
<a href="a.html" target="browse.html"> A   </a>
<a href="b.html" target="browse.html"> B   </a>
<a href="c.html" target="browse.html"> C   </a>
<a href="d.html" target="browse.html"> D   </a>
<a href="e.html" target="browse.html"> E   </a>
<a href="f.html" target="browse.html"> F   </a>
<a href="g.html" target="browse.html"> G   </a>
<a href="h.html" target="browse.html"> H   </a>
<a href="i.html" target="browse.html"> I   </a>
<a href="j.html" target="browse.html"> J   </a>
<a href="k.html" target="browse.html"> K   </a>
<a href="l.html" target="browse.html"> L   </a>
<a href="m.html" target="browse.html"> M   </a>
<a href="n.html" target="browse.html"> N   </a>
<a href="o.html" target="browse.html"> O   </a>
<a href="p.html" target="browse.html"> P   </a>
<a href="q.html" target="browse.html"> Q   </a>
<a href="r.html" target="browse.html"> R   </a>
<a href="s.html" target="browse.html"> S   </a>
<a href="t.html" target="browse.html"> T   </a>
<a href="u.html" target="browse.html"> U   </a>
<a href="v.html" target="browse.html"> V   </a>
<a href="w.html" target="browse.html"> W   </a>
<a href="x.html" target="browse.html"> X   </a>
<a href="y.html" target="browse.html"> Y   </a>
<a href="z.html" target="browse.html"> Z   </a>
</h1>
</div>
</div>
</div>
</body>
</html>