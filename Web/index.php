<?php
	error_reporting(E_ALL);
	ini_set("display_errors", 1);
	$conn = mysqli_connect("localhost", "root", "mm121468", "wdds_db") or die("error");
?>



<html>
<head>
	<title> Wireless Device Detection System </title>
</head>
	<body>
		<form name='skyclad' method='get' action='./index.php'>
			Username : <input type='text' name='username'></br>
			From ( Option ) : <input type='text' name='from'></br>
			To   ( Option ) : <input type='text' name='to'></br>
			<input type='submit' value='Submit'>
		</form>
		<?php
			if(empty($_GET['username'])) echo "[*] Please input username</br>";
			else {
				$query = "SELECT user.name, user.mac_addr, log.time FROM user INNER JOIN `log` WHERE log.mac_addr=user.mac_addr AND user.name='".$_GET['username']."'";
				if(!empty($_GET['to']) && !empty($_GET['from'])){
					$query .= " AND time>'".$_GET['from']."' AND time<='".$_GET['to']."'";
				}
				echo "Query : ".$query."</br>";
				$result = mysqli_query($conn, $query);
				if($result){
					echo "<table style='border:solid 1px;'><tr><td style='border:solid 1px;'>Name</td><td style='border:solid 1px;'>MAC_Addr</td><td style='border:solid 1px;'>Timestamp</td></tr>";
					while($data = mysqli_fetch_array($result)){
						echo "<tr style='border:solid 1px;'>";
						for($i = 0; $i < 3; $i++) echo "<td style='border:solid 1px;'>".$data[$i]."</td>";
						echo "</tr>";
					}
				}
				else echo "[*] No Log!";
			}
		?>
	</body>
</html>
