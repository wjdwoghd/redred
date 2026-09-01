<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();

require_once __DIR__ . '/../database/db.php';
require_once __DIR__ . '/attachment_path.php';


/*
|--------------------------------------------------------------------------
| 공통 파라미터 / 세션 정보
|--------------------------------------------------------------------------
*/

$mode = $_GET['mode'] ?? 'list';

$allowed_modes = [
    'list',
    'write',
    'view',
    'edit'
];

if (!in_array($mode, $allowed_modes, true)) {
    $mode = 'list';
}


$notice_id = $_GET['id'] ?? null;
$keyword = trim((string) ($_GET['keyword'] ?? ''));

$is_logged_in = isset($_SESSION['employee_id']);
$current_employee_id = $is_logged_in ? (int) $_SESSION['employee_id'] : null;

$post_error = null;
$posted_title = '';
$posted_content = '';


/*
|--------------------------------------------------------------------------
| 공지사항 첨부파일 저장 헬퍼
|--------------------------------------------------------------------------
|
| 자료실(resource.php / upload.php)에서 사용하는 방식과 동일하게
| attachments 테이블에 related_type = 'NOTICE' 로 저장합니다.
|
*/

function save_notice_attachment(
    mysqli $conn,
    int $notice_id,
    int $uploader_id,
    array $file,
    string &$error_message
): bool {

    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        $error_message = '첨부파일 업로드 오류 코드: ' . ($file['error'] ?? 'unknown');
        return false;
    }

    $original_name = $file['name'];
    $file_size = $file['size'];
    $content_type = $file['type'];
    $file_tmp = $file['tmp_name'];

    $ext = pathinfo($original_name, PATHINFO_EXTENSION);

    if ($ext === 'php') {
        $error_message = '해당 파일 형식은 업로드할 수 없습니다.';
        return false;
    }

    $stored_name = uniqid('notice_', true) . ($ext ? '.' . $ext : '');

    $relative_path = 'uploads/notices/' . $stored_name;
    $upload_dir = __DIR__ . '/uploads/notices/';

    if (!is_dir($upload_dir)) {
        if (!mkdir($upload_dir, 0777, true)) {
            $error_message = '첨부파일 업로드 폴더를 생성할 수 없습니다. 경로: ' . $upload_dir;
            return false;
        }
    }

    if (!is_writable($upload_dir)) {
        $error_message = '첨부파일 업로드 폴더에 쓸 수 없습니다. 경로: ' . $upload_dir;
        return false;
    }

    $file_path = $upload_dir . $stored_name;

    if (!move_uploaded_file($file_tmp, $file_path)) {
        $error_message = '첨부파일 저장 중 오류가 발생했습니다. 저장 경로: ' . $file_path;
        return false;
    }

    $related_type = 'NOTICE';

    $sql = "INSERT INTO attachments (related_type, related_id, uploader_id, original_name, stored_name, file_path, content_type, file_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        if (file_exists($file_path)) {
            unlink($file_path);
        }
        $error_message = '첨부파일 등록 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error . ' / 저장 경로: ' . $file_path;
        return false;
    }

    $stmt->bind_param(
        'siissssi',
        $related_type,
        $notice_id,
        $uploader_id,
        $original_name,
        $stored_name,
        $relative_path,
        $content_type,
        $file_size
    );

    $ok = $stmt->execute();

    if (!$ok) {
        if (file_exists($file_path)) {
            unlink($file_path);
        }
        $error_message = '첨부파일 등록 중 시스템 오류가 발생했습니다. DB 오류: ' . $stmt->error . ' / 저장 경로: ' . $file_path;
    }

    $stmt->close();

    return $ok;
}


/*
|--------------------------------------------------------------------------
| 기존 공지사항 첨부파일 제거 (파일 + DB 레코드)
|--------------------------------------------------------------------------
*/

function delete_notice_attachments(mysqli $conn, string $notice_id): void
{
    $sql = "SELECT attachment_id, file_path FROM attachments WHERE related_type = 'NOTICE' AND related_id = $notice_id";

    $result = $conn->query($sql);

    if (!$result) {
        die('첨부파일 삭제 준비 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error);
    }

    while ($row = $result->fetch_assoc()) {
        $attachment_path = resolve_attachment_path($row['file_path']);
        if ($attachment_path && file_exists($attachment_path)) {
            unlink($attachment_path);
        }
    }

    $delete_sql = "DELETE FROM attachments WHERE related_type = 'NOTICE' AND related_id = $notice_id";

    if (!$conn->query($delete_sql)) {
        die('첨부파일 삭제 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error);
    }
}


/*
|--------------------------------------------------------------------------
| 등록 / 수정 처리 (POST)
|--------------------------------------------------------------------------
*/

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $post_action = $_POST['action'] ?? '';

    if (in_array($post_action, ['create', 'update'], true)) {

        if (!$is_logged_in) {
            header('Location: login.php');
            exit;
        }

        $posted_title = trim($_POST['title'] ?? '');
        $posted_content = trim($_POST['content'] ?? '');

        if ($posted_title === '' || $posted_content === '') {

            $post_error = '제목과 내용을 모두 입력해 주세요.';
            $mode = ($post_action === 'create') ? 'write' : 'edit';

            if ($post_action === 'update') {
                $notice_id = $_POST['notice_id'] ?? null;
            }

        } elseif ($post_action === 'create') {

            $insert_sql = "INSERT INTO notices (title, content, author_id) VALUES (?, ?, ?)";

            $stmt = $conn->prepare($insert_sql);

            if (!$stmt) {
                die('공지 등록 오류: ' . $conn->error);
            }

            $stmt->bind_param(
                'ssi',
                $posted_title,
                $posted_content,
                $current_employee_id
            );

            if (!$stmt->execute()) {
                die('공지 등록 오류: ' . $conn->error);
            }

            $new_notice_id = (int) $conn->insert_id;
            $stmt->close();

            if (
                isset($_FILES['attachment'])
                && $_FILES['attachment']['error'] === UPLOAD_ERR_OK
            ) {
                $attachment_error = '';

                if (!save_notice_attachment(
                    $conn,
                    $new_notice_id,
                    $current_employee_id,
                    $_FILES['attachment'],
                    $attachment_error
                )) {
                    $post_error = $attachment_error;
                    $mode = 'edit';
                    $notice_id = (string) $new_notice_id;
                }
            }

            if ($post_error === null) {
                header('Location: notices.php?mode=view&id=' . $new_notice_id);
                exit;
            }

        } elseif ($post_action === 'update') {

            $post_notice_id = $_POST['notice_id'] ?? '';

            if (trim((string) $post_notice_id) === '') {

                $post_error = '잘못된 요청입니다.';
                $mode = 'list';

            } else {

                $safe_title = $conn->real_escape_string($posted_title);
                $safe_content = $conn->real_escape_string($posted_content);
                $update_sql = "UPDATE notices SET title = '$safe_title', content = '$safe_content' WHERE notice_id = $post_notice_id";

                if (!$conn->query($update_sql)) {
                    $post_error = '공지 수정 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error;
                    $mode = 'edit';
                } else {
                    if (
                        isset($_FILES['attachment'])
                        && $_FILES['attachment']['error'] === UPLOAD_ERR_OK
                    ) {
                        delete_notice_attachments($conn, (string) $post_notice_id);

                        $attachment_error = '';

                        if (!save_notice_attachment(
                            $conn,
                            $post_notice_id,
                            $current_employee_id,
                            $_FILES['attachment'],
                            $attachment_error
                        )) {
                            $post_error = $attachment_error;
                            $mode = 'edit';
                        }
                    }

                    if ($post_error === null) {
                        header('Location: notices.php?mode=view&id=' . $post_notice_id);
                        exit;
                    }
                }
            }
        }
    }
}


/*
|--------------------------------------------------------------------------
| 삭제 처리 (GET action=delete)
|--------------------------------------------------------------------------
*/

if (($_GET['action'] ?? '') === 'delete' && $notice_id !== null && $notice_id !== false) {

    if (!$is_logged_in) {
        header('Location: login.php');
        exit;
    }

    delete_notice_attachments($conn, (string) $notice_id);

    $delete_notice_sql = "DELETE FROM notices WHERE notice_id = $notice_id";

    if (!$conn->query($delete_notice_sql)) {
        die('공지 삭제 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error);
    }

    header('Location: notices.php');
    exit;
}


/*
|--------------------------------------------------------------------------
| 목록 조회
|--------------------------------------------------------------------------
*/

$notice_list = [];

if ($mode === 'list') {

    $list_sql = "SELECT n.notice_id, n.title, e.name AS author FROM notices n LEFT JOIN employees e ON n.author_id = e.employee_id WHERE n.title LIKE '%$keyword%' OR n.content LIKE '%$keyword%' OR e.name LIKE '%$keyword%' ORDER BY n.notice_id DESC";

    $list_result = $conn->query($list_sql);

    if (!$list_result) {
        die('공지사항 조회 오류: ' . $conn->error);
    }

    while ($row = $list_result->fetch_assoc()) {
        $notice_list[] = $row;
    }
}


/*
|--------------------------------------------------------------------------
| 단건 조회 (view / edit)
|--------------------------------------------------------------------------
*/

$current_notice = null;

if (
    ($mode === 'view' || $mode === 'edit')
    && $notice_id !== false
    && $notice_id !== null
) {

    $detail_sql = "SELECT n.notice_id, n.title, n.content, n.author_id, e.name AS author FROM notices n LEFT JOIN employees e ON n.author_id = e.employee_id WHERE n.notice_id = $notice_id LIMIT 1";
    $detail_result = $conn->query($detail_sql);

    if (!$detail_result) {
        die('공지 상세 조회 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error);
    }

    $current_notice = $detail_result->fetch_assoc() ?: null;

    if ($current_notice !== null) {

        $att_sql = "SELECT attachment_id, original_name, stored_name FROM attachments WHERE related_type = 'NOTICE' AND related_id = $notice_id ORDER BY created_at DESC, attachment_id DESC LIMIT 1";
        $att_result = $conn->query($att_sql);

        if (!$att_result) {
            die('공지 첨부파일 조회 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error);
        }

        $attachment = $att_result->fetch_assoc();

        if ($attachment) {
            $current_notice['attachment_id'] = (int) $attachment['attachment_id'];
            $current_notice['file_name'] = $attachment['original_name'];
            $current_notice['file_url'] = 'uploads/notices/' . $attachment['stored_name'];
        } else {
            $current_notice['attachment_id'] = null;
            $current_notice['file_name'] = null;
            $current_notice['file_url'] = null;
        }

        if ($mode === 'edit' && $post_error === null) {
            $posted_title = $current_notice['title'];
            $posted_content = $current_notice['content'];
        }
    }
}

?>

<!DOCTYPE html>
<html lang='ko'>

<head>

    <meta charset='UTF-8'>

    <meta
        name='viewport'
        content='width=device-width, initial-scale=1.0'
    >

    <title>
        공지사항 | Cortis
    </title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, 'Malgun Gothic', sans-serif;
            background: #f4f6f8;
            color: #333;
        }

        

        header {
            background: #1f2937;
            color: white;
            padding: 22px 0;
        }

        .header-inner {
            width: 1100px;
            margin: auto;
        }

        .logo {
            font-size: 28px;
            font-weight: bold;
        }

        .subtitle {
            margin-top: 5px;
            font-size: 14px;
            color: #d1d5db;
        }

        

        nav {
            background: white;
            border-bottom: 1px solid #ddd;
        }

        .nav-inner {
            width: 1100px;
            margin: auto;
            display: flex;
            align-items: center;
        }

        nav a {
            display: block;
            padding: 18px 30px;
            color: #333;
            text-decoration: none;
            font-size: 15px;
        }

        nav a:hover {
            background: #f1f5f9;
        }

        

        main {
            width: 1100px;
            margin: 35px auto;
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .page-header h2 {
            margin: 0;
        }

        .page-description {
            margin-top: 8px;
            color: #666;
            font-size: 14px;
        }

        

        .button {
            display: inline-block;
            border: none;
            padding: 11px 18px;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
        }

        .button-primary {
            background: #2563eb;
            color: white;
        }

        .button-secondary {
            background: #e5e7eb;
            color: #333;
        }

        .button-danger {
            background: #dc2626;
            color: white;
        }

        .button:hover {
            opacity: 0.9;
        }

        

        .notice-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        .notice-table {
            width: 100%;
            border-collapse: collapse;
        }

        .notice-table th {
            padding: 15px;
            background: #f8fafc;
            border-top: 1px solid #e5e7eb;
            border-bottom: 1px solid #e5e7eb;
            font-size: 14px;
        }

        .notice-table td {
            padding: 15px;
            border-bottom: 1px solid #e5e7eb;
            font-size: 14px;
            text-align: center;
        }

        .notice-table .title {
            text-align: left;
        }

        .notice-table .title a {
            color: #333;
            text-decoration: none;
        }

        .notice-table .title a:hover {
            color: #2563eb;
            text-decoration: underline;
        }

        

        .form-container {
            background: white;
            padding: 35px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        .form-group {
            margin-bottom: 25px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            font-size: 14px;
        }

        .form-group input[type='text'],
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 5px;
            font-family: inherit;
            font-size: 14px;
        }

        .form-group textarea {
            height: 300px;
            resize: vertical;
        }

        .form-group input[readonly],
        .form-group textarea[readonly] {
            background: #f8fafc;
            color: #555;
        }

        .form-group input[type='file'] {
            padding: 8px 0;
        }

        .current-file {
            margin-bottom: 12px;
            padding: 12px;
            background: #f8fafc;
            border: 1px solid #e5e7eb;
            border-radius: 5px;
            font-size: 14px;
        }

        .current-file .download {
            margin-left: 10px;
            color: #2563eb;
            text-decoration: none;
            font-weight: bold;
        }

        .current-file .download:hover {
            text-decoration: underline;
        }

        .button-area {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            margin-top: 30px;
        }

        .notice-meta {
            display: flex;
            gap: 25px;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e5e7eb;
            color: #666;
            font-size: 14px;
        }

        .empty-message {
            text-align: center;
            padding: 50px;
            color: #777;
        }

        .search-form {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .search-form input {
            flex: 1;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 5px;
            font: inherit;
        }

        .search-keyword {
            margin: 0 0 18px;
            color: #475569;
            font-size: 14px;
        }

        .readonly-display {
            width: 100%;
            min-height: 44px;
            padding: 12px;
            background: #f8fafc;
            border: 1px solid #d1d5db;
            border-radius: 5px;
            color: #555;
            font-size: 14px;
            line-height: 1.7;
            white-space: pre-wrap;
        }

        .readonly-display.content {
            min-height: 300px;
        }

        .form-error {
            margin-bottom: 20px;
            padding: 12px 15px;
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            border-radius: 5px;
            font-size: 14px;
        }

        

        footer {
            margin-top: 60px;
            background: #1f2937;
            color: #aaa;
            text-align: center;
            padding: 25px;
            font-size: 13px;
        }

    </style>
    <link rel="stylesheet" href="logo.css">

</head>

<body>

<header>

    <div class='header-inner'>

        <a class='cortis-logo-link' href='index.php' aria-label='Cortis 홈'>
            <img class='cortis-logo-image' src='Cortis_로고.png' alt='Cortis'>
        </a>

        <div class='subtitle'>
            Company Internal Management System
        </div>

    </div>

</header>


<nav>

    <div class='nav-inner'>

        <a href='index.php'>
            홈
        </a>

        <a href='login.php'>
            로그인
        </a>

        <a href='resource.php'>
            자료실
        </a>

        <a href='department.php'>
            부서
        </a>

        <a href='notices.php'>
            공지사항
        </a>

    </div>

</nav>


<main>

<?php if ($mode === 'list'): ?>

    <div class='page-header'>

        <div>

            <h2>
                공지사항
            </h2>

            <div class='page-description'>
                Cortis의 주요 공지사항을 확인할 수 있습니다.
            </div>

        </div>

        <a
            href='notices.php?mode=write'
            class='button button-primary'
        >
            글쓰기
        </a>

    </div>


    <section class='notice-container'>

        <form class='search-form' method='get' action='notices.php'>
            <input type='hidden' name='mode' value='list'>
            <input type='search' name='keyword' value='<?= $keyword ?>' placeholder='공지 제목, 내용, 작성자 검색' aria-label='공지 검색어'>
            <button type='submit' class='button button-primary'>검색</button>
        </form>

        <?php if ($keyword !== ''): ?>
            <p class='search-keyword'>검색어: <?= $keyword ?></p>
        <?php endif; ?>

        <table class='notice-table'>

            <thead>

                <tr>

                    <th style='width: 90px;'>
                        번호
                    </th>

                    <th>
                        제목
                    </th>

                    <th style='width: 140px;'>
                        작성자
                    </th>

                </tr>

            </thead>

            <tbody>

            <?php if (count($notice_list) === 0): ?>

                <tr>

                    <td colspan='3' class='empty-message'>
                        등록된 공지사항이 없습니다.
                    </td>

                </tr>

            <?php else: ?>

                <?php foreach ($notice_list as $notice): ?>

                    <tr>

                        <td>
                            <?= htmlspecialchars(
                                (string) $notice['notice_id']
                            ) ?>
                        </td>

                        <td class='title'>

                            <a
                                href='notices.php?mode=view&id=<?= urlencode(
                                    (string) $notice['notice_id']
                                ) ?>'
                            >
                                <?= $notice['title'] ?>
                            </a>

                        </td>

                        <td>
                            <?= htmlspecialchars(
                                $notice['author'] ?? '알 수 없음'
                            ) ?>
                        </td>

                    </tr>

                <?php endforeach; ?>

            <?php endif; ?>

            </tbody>

        </table>

    </section>


<?php elseif ($mode === 'write'): ?>

    <div class='page-header'>

        <div>

            <h2>
                공지사항 등록
            </h2>

            <div class='page-description'>
                새로운 공지사항을 작성합니다.
            </div>

        </div>

    </div>


    <section class='form-container'>

        <?php if ($post_error !== null): ?>

            <div class='form-error'>
                <?= htmlspecialchars($post_error) ?>
            </div>

        <?php endif; ?>


        <?php if (!$is_logged_in): ?>

            <div class='form-error'>
                공지사항 등록은 로그인 후 이용할 수 있습니다.
                <a href='login.php'>로그인 하러 가기</a>
            </div>

        <?php else: ?>

        <form
            action='notices.php?mode=write'
            method='post'
            enctype='multipart/form-data'
        >

            <input
                type='hidden'
                name='action'
                value='create'
            >


            <div class='form-group'>

                <label for='title'>
                    제목
                </label>

                <input
                    type='text'
                    id='title'
                    name='title'
                    maxlength='200'
                    value='<?= htmlspecialchars($posted_title) ?>'
                    required
                >

            </div>


            <div class='form-group'>

                <label for='content'>
                    내용
                </label>

                <textarea
                    id='content'
                    name='content'
                    required
                ><?= htmlspecialchars($posted_content) ?></textarea>

            </div>


            <div class='form-group'>

                <label for='attachment'>
                    파일 첨부
                </label>

                <input
                    type='file'
                    id='attachment'
                    name='attachment'
                >

            </div>


            <div class='button-area'>

                <a
                    href='notices.php'
                    class='button button-secondary'
                >
                    취소
                </a>

                <button
                    type='submit'
                    class='button button-primary'
                >
                    등록
                </button>

            </div>

        </form>

        <?php endif; ?>

    </section>


<?php elseif ($mode === 'view'): ?>

    <?php if ($current_notice === null): ?>

        <section class='notice-container'>

            <div class='empty-message'>

                존재하지 않는 공지사항입니다.

                <br><br>

                <a
                    href='notices.php'
                    class='button button-secondary'
                >
                    목록으로
                </a>

            </div>

        </section>

    <?php else: ?>

        <div class='page-header'>

            <div>

                <h2>
                    공지사항 상세
                </h2>

                <div class='page-description'>
                    공지사항 내용을 확인합니다.
                </div>

            </div>

        </div>


        <section class='form-container'>

            <div class='notice-meta'>

                <span>
                    번호:
                    <?= htmlspecialchars(
                        (string) $current_notice['notice_id']
                    ) ?>
                </span>

                <span>
                    작성자:
                    <?= htmlspecialchars(
                        $current_notice['author'] ?? '알 수 없음'
                    ) ?>
                </span>

            </div>


            <div class='form-group'>

                <label>
                    제목
                </label>

                <div class='readonly-display'><?= $current_notice['title'] ?></div>

            </div>


            <div class='form-group'>

                <label>
                    내용
                </label>

                <div class='readonly-display content'><?= $current_notice['content'] ?></div>

            </div>


            <div class='form-group'>

                <label>
                    첨부파일
                </label>

                <?php if ($current_notice['file_name'] !== null): ?>

                    <div class='current-file'>

                        <?= $current_notice['file_name'] ?>

                        <a
                            class='download'
                            href='download.php?id=<?= urlencode(
                                (string) $current_notice['attachment_id']
                            ) ?>'
                        >
                            다운로드
                        </a>
                        <a
                            class='download'
                            href='<?= $current_notice['file_url'] ?>'
                            target='_blank'
                            rel='noopener'
                        >
                            열기
                        </a>

                    </div>

                <?php else: ?>

                    <div class='current-file'>
                        첨부파일이 없습니다.
                    </div>

                <?php endif; ?>

            </div>


            <div class='button-area'>

                <a
                    href='notices.php'
                    class='button button-secondary'
                >
                    목록
                </a>

                

                <a
                    href='notices.php?mode=edit&id=<?= urlencode(
                        (string) $current_notice['notice_id']
                    ) ?>'
                    class='button button-primary'
                >
                    수정
                </a>


                

                <button
                    type='button'
                    class='button button-danger'
                    onclick='confirmDelete(<?= (int) $current_notice['notice_id'] ?>);'
                >
                    삭제
                </button>

            </div>

        </section>

    <?php endif; ?>


<?php elseif ($mode === 'edit'): ?>

    <?php if ($current_notice === null): ?>

        <section class='notice-container'>

            <div class='empty-message'>

                존재하지 않는 공지사항입니다.

                <br><br>

                <a
                    href='notices.php'
                    class='button button-secondary'
                >
                    목록으로
                </a>

            </div>

        </section>

    <?php else: ?>

        <div class='page-header'>

            <div>

                <h2>
                    공지사항 수정
                </h2>

                <div class='page-description'>
                    공지사항 내용을 수정합니다.
                </div>

            </div>

        </div>


        <section class='form-container'>

            <?php if ($post_error !== null): ?>

                <div class='form-error'>
                    <?= htmlspecialchars($post_error) ?>
                </div>

            <?php endif; ?>

            

            <form
                action='notices.php?mode=edit&id=<?= urlencode(
                    (string) $current_notice['notice_id']
                ) ?>'
                method='post'
                enctype='multipart/form-data'
            >

                <input
                    type='hidden'
                    name='action'
                    value='update'
                >

                <input
                    type='hidden'
                    name='notice_id'
                    value='<?= htmlspecialchars(
                        (string) $current_notice['notice_id']
                    ) ?>'
                >


                <div class='form-group'>

                    <label for='edit-title'>
                        제목
                    </label>

                    <input
                        type='text'
                        id='edit-title'
                        name='title'
                        maxlength='200'
                        value='<?= htmlspecialchars($posted_title) ?>'
                        required
                    >

                </div>


                <div class='form-group'>

                    <label for='edit-content'>
                        내용
                    </label>

                    <textarea
                        id='edit-content'
                        name='content'
                        required
                    ><?= htmlspecialchars($posted_content) ?></textarea>

                </div>


                <div class='form-group'>

                    <label>
                        기존 첨부파일
                    </label>

                    <div class='current-file'>

                        <?php if ($current_notice['file_name'] !== null): ?>

                            <?= $current_notice['file_name'] ?>

                            <a
                                class='download'
                                href='download.php?id=<?= urlencode(
                                    (string) $current_notice['attachment_id']
                                ) ?>'
                            >
                                다운로드
                            </a>

                        <?php else: ?>

                            첨부파일이 없습니다.

                        <?php endif; ?>

                    </div>

                </div>


                <div class='form-group'>

                    <label for='edit-attachment'>
                        새 파일 첨부
                    </label>

                    <input
                        type='file'
                        id='edit-attachment'
                        name='attachment'
                    >

                    <div class='page-description'>
                        새 파일을 첨부하면 기존 첨부파일은 교체됩니다.
                    </div>

                </div>


                <div class='button-area'>

                    <a
                        href='notices.php?mode=view&id=<?= urlencode(
                            (string) $current_notice['notice_id']
                        ) ?>'
                        class='button button-secondary'
                    >
                        취소
                    </a>

                    <button
                        type='submit'
                        class='button button-primary'
                    >
                        수정 완료
                    </button>

                </div>

            </form>

        </section>

    <?php endif; ?>

<?php endif; ?>

</main>


<footer>

    Cortis &copy; 2026

</footer>


<script>

    function confirmDelete(noticeId) {

        if (confirm('정말 삭제하시겠습니까?')) {
            location.href = 'notices.php?action=delete&id=' + noticeId;
        }

    }

</script>

</body>

</html>
