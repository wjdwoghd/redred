<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();

// 1. 로그인 확인
if (!isset($_SESSION["employee_id"])) {
    header("Location: login.php");
    exit;
}

// 2. 파라미터 검증
$attachment_id = $_GET['id'] ?? '';
if (trim((string) $attachment_id) === '') {
    echo "<script>alert('잘못된 요청입니다.'); location.href='resource.php';</script>";
    exit;
}

require_once __DIR__ . '/../database/db.php';
require_once __DIR__ . '/attachment_path.php';

// 3. 파일 경로 조회
$sql = "SELECT file_path FROM attachments WHERE attachment_id = $attachment_id";
$select_result = $conn->query($sql);

if (!$select_result) {
    echo "<script>alert('자료 삭제 준비 중 시스템 오류가 발생했습니다. DB 오류: " . htmlspecialchars($conn->error, ENT_QUOTES, 'UTF-8') . "'); location.href='resource.php';</script>";
    exit;
}

$result = $select_result->fetch_assoc();

if ($result) {
    $file_path = resolve_attachment_path($result['file_path']);

    // 4. 실제 파일 삭제
    if (file_exists($file_path)) {
        unlink($file_path);
    }

    // 5. DB 레코드 삭제
    $del_sql = "DELETE FROM attachments WHERE attachment_id = $attachment_id";

    if (!$conn->query($del_sql)) {
        echo "<script>alert('자료 삭제 중 시스템 오류가 발생했습니다. DB 오류: " . htmlspecialchars($conn->error, ENT_QUOTES, 'UTF-8') . "'); location.href='resource.php';</script>";
        exit;
    }

    echo "<script>alert('성공적으로 삭제되었습니다.'); location.href='resource.php';</script>";
} else {
    echo "<script>alert('존재하지 않는 자료입니다.'); location.href='resource.php';</script>";
}

$conn->close();
exit;
?>
