<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();

/* 1. 로그인 확인 */
if (!isset($_SESSION["employee_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . '/../database/db.php';

$logged_in_user_id = $_SESSION["employee_id"];


/* 2. 관리자 권한 여부 확인 */
$user_sql = "SELECT role FROM employees WHERE employee_id = ?";

$user_stmt = $conn->prepare($user_sql);
$user_stmt->bind_param("i", $logged_in_user_id);
$user_stmt->execute();

$user_result = $user_stmt->get_result()->fetch_assoc();


/* 3. 관리자가 아니면 업로드 페이지 접근 차단 */
if (!$user_result || $user_result["role"] !== "ADMIN") {

    http_response_code(403);

    echo "
        <script>
            alert('관리자만 파일을 업로드할 수 있습니다.');
            location.href='resource.php';
        </script>
    ";

    exit;
}


$error = "";


/* 4. 파일 업로드 처리 */
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $uploader_id = $_SESSION["employee_id"];


    /* 파일 선택 여부 확인 */
    if (
        isset($_FILES["file"]) &&
        $_FILES["file"]["error"] === UPLOAD_ERR_OK
    ) {

        $file = $_FILES["file"];

        $original_name = $file["name"];
        $file_size = $file["size"];
        $content_type = $file["type"];
        $file_tmp = $file["tmp_name"];


        /* 확장자 추출 */
        $parts = explode('.', $original_name);
        $ext = end($parts);


        /* 블랙리스트 설정 및 검증 */
        $blacklist = array("php", "jsp", "asp", "exe", "html");


        if (in_array($ext, $blacklist)) {
            
            $error = "보안 정책에 의해 해당 파일(.{$ext})은 업로드할 수 없습니다.";

        } else {

            /* 원래 파일명 그대로 사용 */
            $stored_name = $original_name;


            /* 업로드 폴더 */
            $upload_dir = __DIR__ . "/uploads/resource/";


            /* 폴더가 없으면 생성 */
            if (!is_dir($upload_dir)) {
                if (!mkdir($upload_dir, 0777, true)) {
                    $error = "업로드 폴더를 생성할 수 없습니다. 경로: " . $upload_dir;
                }
            }

            if ($error === "" && !is_writable($upload_dir)) {
                $error = "업로드 폴더에 쓸 수 없습니다. 경로: " . $upload_dir;
            }


            /* 폴더 생성에 성공했거나 이미 존재하는 경우 */
            if ($error === "") {

                $relative_path = 'uploads/resource/' . $stored_name;
                $file_path = $upload_dir . $stored_name;


                /* 파일 이동 */
                if (move_uploaded_file($file_tmp, $file_path)) {

                    $related_type = "RESOURCE";
                    $related_id = 0;


                    /* DB 저장 */
                    $sql = "
                        INSERT INTO attachments
                        (
                            related_type,
                            related_id,
                            uploader_id,
                            original_name,
                            stored_name,
                            file_path,
                            content_type,
                            file_size
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ";


                    $stmt = $conn->prepare($sql);

                    if (!$stmt) {
                        if (file_exists($file_path)) {
                            unlink($file_path);
                        }
                        $error = "DB 저장 준비 실패: " . $conn->error . " / 저장 경로: " . $file_path;
                    } else {

                    $stmt->bind_param(
                        "siissssi",
                        $related_type,
                        $related_id,
                        $uploader_id,
                        $original_name,
                        $stored_name,
                        $relative_path,
                        $content_type,
                        $file_size
                    );


                    if ($stmt->execute()) {

                        echo "
                            <script>
                                alert('자료가 업로드되었습니다.\\n업로드 경로: uploads/resource/" . addslashes($stored_name) . "');
                                location.href='resource.php';
                            </script>
                        ";

                        exit;

                    } else {

                        /* DB 저장 실패 시 이미 저장된 파일 삭제 */
                        if (file_exists($file_path)) {
                            unlink($file_path);
                        }

                        $error = "DB 저장 실패: " . $stmt->error . " / 저장 경로: " . $file_path;
                    }

                    $stmt->close();

                    }

                } else {
                    $error = "파일 저장 중 오류가 발생했습니다. 저장 경로: " . $file_path;
                }
            }
        }

    } else {
        $error = "파일을 선택해 주세요.";
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>자료 등록 | Cortis</title>
    <style>
        body { font-family: Arial, "Malgun Gothic", sans-serif; background: #f4f6f8; margin: 0; padding: 40px; }
        .upload-card { max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        h2 { margin-top: 0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="file"] { width: 100%; padding: 8px; }
        .btn-submit { background: #2563eb; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; width: 100%; font-size: 15px; }
        .btn-submit:hover { background: #1d4ed8; }
        .error { color: #ef4444; margin-bottom: 15px; font-size: 14px; }
    </style>
    <link rel="stylesheet" href="logo.css">
</head>
<body>
    <div class="upload-card">
        <a class="cortis-logo-link cortis-logo-link--card" href="index.php" aria-label="Cortis 홈">
            <img class="cortis-logo-image" src="Cortis_로고.png" alt="Cortis">
        </a>
        <h2>자료 등록</h2>

        <?php if ($error): ?>
            <div class="error">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form action="upload.php" method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label>첨부할 파일 선택</label>
                <input type="file" name="file" required>
            </div>
            <button type="submit" class="btn-submit">업로드</button>
        </form>
    </div>
</body>
</html>
