<?php
session_start();
include "./config.php";

function xssFilter4Board($target)
{
	$target = str_replace("<iframe", "&lt;iframe", $target);
	preg_match_all("\&;iframe[^>]*src=[']?([^>']+)[']?[^>]*>/", $target, $target);
    $arrchn = array("onabort","onactivate","onafterprint","onafterupdate",	
    "onbeforeactivate",	"onbeforecopy","onbeforecut","onbeforedeactivate","onbeforeeditfocus",
    "onbeforepaste","onbeforeprint","onbeforeunload","onbeforeupdate","onbegin","onblur","onbounce",
    "oncellchange",	"onchange",	"onclick","oncontentready","oncontentsave","oncontextmenu",
    "oncontrolselect","oncopy",	"oncut","ondataavailable","ondatasetchanged","ondatasetcomplete",
    "ondblclick","ondeactivate","ondetach","ondocumentready","ondrag","ondragdrop",	"ondragend",	
    "ondragenter","ondragleave","ondragover","ondragstart",	"ondrop","onend",
    "onerror",	"onerrorupdate","onfilterchange","onfinish","onfocus","onfocusin",	
    "onfocusout","onhelp","onhide","onkeydown","onkeypress","onkeyup","onlayoutcomplete",
    "onload","onlosecapture","onmediacomplete","onmediaerror","onmedialoadfailed",	
    "onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover",	
    "onmouseup","onmousewheel","onmove","onmoveend","onmovestart","onopenstatechange",
    "onoutofsync","onpaste","onpause","onplaystatechange","onpropertychange",				
    "onreadystatechange","onrepeat","onreset","onresize","onresizeend","onresizestart","onresume",
    "onreverse","onrowclick","onrowenter","onrowexit","onrowout","onrowover","onrowsdelete",				"onrowsinserted",	
    "onsave","onscroll","onseek","onselect","onselectionchange","onselectstart",		
    "onshow","onstart","onstop","onsubmit","onsyncrestored","ontimeerror",
    "ontrackchange","onunload","onurlflip", "javascript");
    for($j=0;$j<sizeof($arrchn);$j++){
        $target = str_replace($arrchn[j], "", $target);
    }
	$target = str_replace("<script", "&lt;script", $target);
	$target = str_replace("</script>", "&lt;script&gt;", $target);
	$target = str_replace("<input", "&lt;input", $target);
	$target = str_replace("</input>", "&lt;input&gt;", $target);
	$target = str_replace("<form", "&lt;from", $target);
	$target = str_replace("</form>", "&lt;/form&gt", $target);
	$target = str_replace("<textarea", "&lt;textarea", $target);
	$target = str_replace("</textarea", "&lt;textarea&gt", $target);
	$target = str_replace("<meta", "&lt;meta", $target);
	$target = str_replace("</meta>", "&lt;meta&gt;", $target);
	return $target;
}

if($_GET['page'] == "login"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    
    $id = htmlspecialchars(addslashes($input['id']), ENT_QUOTES, 'UTF-8'); // my
    $pw = htmlspecialchars(addslashes($input['pw']), ENT_QUOTES, 'UTF-8'); // my
    
    //$id = $input['id'];
    //$pw = $input['pw'];
    
    if(isset($id) && isset($pw) && !empty($id) && !empty($pw))
    {
        $db = dbconnect();
        //$query = "select id,pw from member where id='{$id}'";
        //$result = mysqli_fetch_array(mysqli_query($db,$query));
        
        //$stmt = $db->stmt_init();
        $query = "select id,pw from member where id= ?";
        $stmt = $db->prepare($query);
        $stmt->bind_param("s", $id);
        
        $stmt->execute();
        $result = $stmt->get_result();
        $result = $result->fetch_assoc();
        
        if($result['id'] && $result['pw'] == $pw){
            $_SESSION['id'] = $result['id'];
            $_SESSION['pw'] = $result['pw'];
            exit("<script>alert(`login ok`);location.href=`/`;</script>");
        }
        else{ exit("<script>alert(`login fail`);history.go(-1);</script>"); }
    }
    else{ exit("<script>alert(`login fail`);history.go(-1);</script>"); }
}
if($_GET['page'] == "join"){
    try{
        $input = json_decode(file_get_contents('php://input'), true);
    }
    catch(Exception $e){
        exit("<script>alert(`wrong input`);history.go(-1);</script>");
    }
    
    $id = htmlspecialchars(addslashes($input['id']), ENT_QUOTES, 'UTF-8'); // my
    $pw = htmlspecialchars(addslashes($input['pw']), ENT_QUOTES, 'UTF-8'); // my
    $email = htmlspecialchars(addslashes($input['email']), ENT_QUOTES, 'UTF-8'); //my
    
    if(isset($id) && isset($pw) && isset($email) && !empty($id) && !empty($pw) && !empty($email))
    {
        $db = dbconnect();
        if(strlen($id) > 256) exit("<script>alert(`userid too long`);history.go(-1);</script>");
        if(strlen($email) > 120) exit("<script>alert(`email too long`);history.go(-1);</script>");
        if(!filter_var($email,FILTER_VALIDATE_EMAIL)) exit("<script>alert(`wrong email`);history.go(-1);</script>");
        //$query = "select id from member where id='{$id}'";
        //$result = mysqli_fetch_array(mysqli_query($db,$query));
        
        $query = "select id,pw from member where id= ?";
        $stmt = $db->prepare($query);
        $stmt->bind_param("s", $id);
        
        $stmt->execute();
        $result = $stmt->get_result();
        $result = $result->fetch_assoc();
        
        if(!$result['id']){
            //$query = "insert into member values('{$id}','{$email}','{$pw}','user')";
            //mysqli_query($db,$query);
            
            $query = "insert into member values(?, ?, ?,'user')";
            $stmt = $db->prepare($query);
            $stmt->bind_param("sss", $id, $email, $pw);
            
            $stmt->execute();
            exit("<script>alert(`join ok`);location.href=`/`;</script>");
        }
        else{
            exit("<script>alert(`Userid already existed`);history.go(-1);</script>");
        }
    }
    else{
            exit("<script>alert(`Userid already existed`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "upload"){
    if(!$_SESSION['id']){
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    if($_SESSION['id'] == $result['id']){
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    
    //$filename=$_FILES['fileToUpload']['name'];
    //$filetype=$_FILES['fileToUpload']['type'];
    //$filename = htmlspecialchars($filename, ENT_QUOTES, 'UTF-8');
    //$filetype = strtolower($filetype);
    
    //$filename = htmlentities($_FILES['fileToUpload']['name'], ENT_QUOTES, 'UTF-8');
    //$filename_tmp_name = htmlentities($_FILES['fileToUpload']['tmp_name'], ENT_QUOTES, 'UTF-8');
    $filename = xssFilter4Board($_FILES['fileToUpload']['name']);
    $filename_tmp_name = xssFilter4Board($_FILES['fileToUpload']['tmp_name']);
    
    if($_FILES['fileToUpload']['size'] >= 1024 * 1024 * 1){ 
        exit("<script>alert(`file is too big`);history.go(-1);</script>"); 
    } // file size limit(1MB). do not remove it.
    $extension = explode(".",$filename)[1];
    if($extension == "txt" || $extension == "png"){
        system("cp {$filename_tmp_name} ./upload/{$filename}");
        // ------------------------ command injection
        exit("<script>alert(`upload ok`);location.href=`/`;</script>");
    }
    else{
        exit("<script>alert(`txt or png only`);history.go(-1);</script>");
    }
}
if($_GET['page'] == "download"){
    //$path = htmlentities($_GET['file'], ENT_QUOTES, 'UTF-8');
    $path = htmlentities(xssFilter4Board($_GET['file']), ENT_QUOTES, 'UTF-8');
    $content = xssFilter4Board(file_get_contents("./upload/{$path}")); // ---------path traversal, ssrf
    $content = str_replace("..", "aa", $content);
    if(!$content){
        exit("<script>alert(`not exists file`);history.go(-1);</script>");
    }
    else{
        header("Content-Disposition: attachment;");
        echo $content; // -------------- xss
        exit;
    }
}
if($_GET['page'] == "admin"){
    if(!$_SESSION['id']){
        exit("<script>alert(`login plz`);history.go(-1);</script>");
    }
    $db = dbconnect();
    //$result = mysqli_fetch_array(mysqli_query($db,"select id from member where id='{$_SESSION['id']}'"));
    $query = "select id from member where id= ?";
    $stmt = $db->prepare($query);
    $stmt->bind_param("s", $_SESSION['id']);
    
    $stmt->execute();
    $result = $stmt->get_result();
    $result = $result->fetch_assoc();
    if($result['id'] == "admin"){
        echo file_get_contents("/flag"); // do not remove it. --------- xss
    }
    else{
        exit("<script>alert(`admin only`);history.go(-1);</script>");
    }
}

/*  this is hint. you can remove it.
CREATE TABLE `member` (
    `id` varchar(120) NOT NULL,
    `email` varchar(120) NOT NULL,
    `pw` varchar(120) NOT NULL,
    `type` varchar(5) NOT NULL
  );
  
  INSERT INTO `member` (`id`, `email`, `pw`, `type`)
      VALUES ('admin', '**SECRET**', '**SECRET**', 'admin');
*/

?>
