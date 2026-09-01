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
$attachment_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($attachment_id <= 0) {
    echo "<script>alert('잘못된 요청입니다.'); location.href='resource.php';</script>";
    exit;
}

require_once __DIR__ . '/../database/db.php';
require_once __DIR__ . '/attachment_path.php';

// 3. DB 조회 (attachments 테이블)
$sql = "SELECT original_name, stored_name, file_path, content_type FROM attachments WHERE attachment_id = ?";
$stmt = $conn->prepare($sql);

if (!$stmt) {
    echo "<script>alert('파일 조회 중 시스템 오류가 발생했습니다. DB 오류: " . addslashes($conn->error) . "'); location.href='resource.php';</script>";
    exit;
}

$stmt->bind_param("i", $attachment_id);

if (!$stmt->execute()) {
    echo "<script>alert('파일 조회 중 시스템 오류가 발생했습니다. DB 오류: " . addslashes($stmt->error) . "'); location.href='resource.php';</script>";
    exit;
}

$result = $stmt->get_result()->fetch_assoc();

if (!$result) {
    echo "<script>alert('존재하지 않는 파일입니다.'); location.href='resource.php';</script>";
    exit;
}

$original_name = $result['original_name'];
$file_path = resolve_attachment_path($result['file_path']);

// 4. 파일 존재 유무 검증
if (!file_exists($file_path)) {
    echo "<script>alert('서버에서 파일을 찾을 수 없습니다. 경로: " . addslashes($file_path) . "'); location.href='resource.php';</script>";
    exit;
}

if (!is_readable($file_path)) {
    echo "<script>alert('파일을 읽을 권한이 없습니다. 경로: " . addslashes($file_path) . "'); location.href='resource.php';</script>";
    exit;
}

// 5. 한글 파일명 깨짐 방지
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
if (preg_match('/MSIE|TRIDENT/i', $ua)) {
    $encoded_filename = rawurlencode($original_name);
} else {
    $encoded_filename = '"' . addslashes($original_name) . '"';
}

// 6. 다운로드 헤더 전송
header('Content-Description: File Transfer');
header('Content-Type: ' . ($result['content_type'] ?: 'application/octet-stream'));
header('Content-Disposition: attachment; filename=' . $encoded_filename . '; filename*=UTF-8\'\'' . rawurlencode($original_name));
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . filesize($file_path));

if (ob_get_level()) {
    ob_end_clean();
}
readfile($file_path);

$conn->close();
exit;
?>
