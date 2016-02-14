<?php
	error_reporting(E_ALL);
	ini_set("display_errors", 1);
	$conn = mysqli_connect("localhost", "ID", "PASSWD", "wdds_db") or die("error");
?>

<html>
<head>
	<title> Wireless Device Detection System </title>
</head>
<body>
	
		
		<form name='skyclad' method='get' action='./chart.php'>
			Username : <input type='text' name='username' value=<?php if(!empty($_GET['username'])) echo "'".$_GET['username']."'"; ?>></br>
			MAC_ADDR : <input type='text' name='mac_addr' value=<?php if(!empty($_GET['mac_addr'])) echo "'".$_GET['mac_addr']."'"; ?>></br>
			From ( Option ) : <input type='text' name='from' value=<?php if(!empty($_GET['from'])) echo "'".$_GET['from']."'"; ?>></br>
			To   ( Option ) : <input type='text' name='to' value=<?php if(!empty($_GET['to'])) echo "'".$_GET['to']."'"; ?>></br>
			<input type='submit' value='Submit'>
		</form>
		
		<?php
		$query = "SELECT DISTINCT(log.time) FROM `log` inner join user where user.mac_addr=log.mac_addr";		
		if(!empty($_GET['username'])) $query .= " and user.name='".$_GET['username']."'";
		if(!empty($_GET['mac_addr'])) $query .= " and user.mac_addr='".$_GET['mac_addr']."'";
		if(!empty($_GET['from']) && !empty($_GET['to'])) $query .= " and log.time>'".$_GET['from']."' and log.time<='".$_GET['to']."'";
		echo $query."</br>";		
		$result = mysqli_query($conn, $query);
		$timeList = array();

		while($row = mysqli_fetch_assoc($result)) {
			$timeList[] = $row['time'];										// <= MySQL Json Encoding
		}

		echo "</br></br>";
		
		$query = "SELECT log.flag FROM `log` inner join user where user.mac_addr=log.mac_addr";		
		if(!empty($_GET['username'])) $query .= " and user.name='".$_GET['username']."'";
		if(!empty($_GET['from']) && !empty($_GET['to'])) $query .= " and log.time>'".$_GET['from']."' and log.time<='".$_GET['to']."'";
		echo $query."</br>";	
		$result = mysqli_query($conn, $query);
		$data = array();

		while($row = mysqli_fetch_assoc($result)) {
			$data[] = $row['flag'];										// <= MySQL Json Encoding
		}			
			
		
		?>
		
		<script src="Chart.js"></script>
	<canvas id="myChart" width="1200" height="400"></canvas>
	<script>
		var ctx = document.getElementById("myChart").getContext("2d");
		
		var options = {
		    ///Boolean - Whether grid lines are shown across the chart
		    scaleShowGridLines : true,
		
		    //String - Colour of the grid lines
		    scaleGridLineColor : "rgba(0,0,0,.05)",
		
		    //Number - Width of the grid lines
		    scaleGridLineWidth : 1,
		
		    //Boolean - Whether to show horizontal lines (except X axis)
		    scaleShowHorizontalLines: true,
		
		    //Boolean - Whether to show vertical lines (except Y axis)
		    scaleShowVerticalLines: true,
		
		    //Boolean - Whether the line is curved between points
		    bezierCurve : true,

		    //Number - Tension of the bezier curve between points
		    bezierCurveTension : 0.4,

		    //Boolean - Whether to show a dot for each point
		    pointDot : true,

 		   //Number - Radius of each point dot in pixels
		    pointDotRadius : 4,

		    //Number - Pixel width of point dot stroke
		    pointDotStrokeWidth : 1,

		    //Number - amount extra to add to the radius to cater for hit detection outside the drawn point
		    pointHitDetectionRadius : 20,

		    //Boolean - Whether to show a stroke for datasets
		    datasetStroke : true,

		    //Number - Pixel width of dataset stroke
		    datasetStrokeWidth : 2,

		    //Boolean - Whether to fill the dataset with a colour
		    datasetFill : true,

		    //String - A legend template
   		 legendTemplate : "<ul class=\"<%=name.toLowerCase()%>-legend\"><% for (var i=0; i<datasets.length; i++){%><li><span style=\"background-color:<%=datasets[i].strokeColor%>\"></span><%if(datasets[i].label){%><%=datasets[i].label%><%}%></li><%}%></ul>"

		};
	
		var data = {
    labels: <?php echo json_encode($timeList); ?>,
    datasets: [
        {
            label: "My First dataset",
            fillColor: "rgba(0,0,0, 1)",
            strokeColor: "rgba(220,220,220,0.8)",
            highlightFill: "rgba(220,220,220,0.75)",
            highlightStroke: "rgba(220,220,220,1)",
            data: <?php echo json_encode($data); ?>
        }
    ]
};
		
		var myBarChart = new Chart(ctx).Bar(data, options);
			
	</script>
</body>
