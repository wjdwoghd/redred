<?php

declare(strict_types=1);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();

require_once __DIR__ . '/department_data.php';
require_once __DIR__ . '/department_layout.php';
require_once __DIR__ . '/../database/db.php';

$departmentKey = $_GET['dept'] ?? '';

if (!isset($department[$departmentKey])) {
    http_response_code(404);
    exit('부서 정보를 찾을 수 없습니다.');
}

$department = $department[$departmentKey];
$departmentIdMap = ['hr' => 1, 'administration' => 2, 'finance' => 3, 'planning' => 4, 'design' => 5, 'sales' => 6];
$departmentId = $departmentIdMap[$departmentKey] ?? 0;
$keyword = trim((string) ($_GET['keyword'] ?? ''));
$submitted = $_SERVER['REQUEST_METHOD'] === 'POST';
$uploadMessage = '';
$uploadError = '';
$uploadedUrl = '';

if ($submitted) {
    $resourceTitle = trim((string) ($_POST['title'] ?? ''));
    $uploaderId = (int) ($_SESSION['employee_id'] ?? 1);

    if ($resourceTitle === '') {
        $uploadError = '자료 제목을 입력해 주세요.';
    } elseif (!isset($_FILES['resource_file']) || $_FILES['resource_file']['error'] !== UPLOAD_ERR_OK) {
        $uploadError = '업로드할 파일을 선택해 주세요.';
    } else {
        $file = $_FILES['resource_file'];
        $originalName = $file['name'];
        $fileSize = (int) $file['size'];
        $contentType = $file['type'] ?: 'application/octet-stream';
        $fileTmp = $file['tmp_name'];
        $ext = pathinfo($originalName, PATHINFO_EXTENSION);

        if ($ext === 'php') {
            $uploadError = '해당 파일 형식은 업로드할 수 없습니다.';
        } else {
            $storedName = uniqid('department_', true) . ($ext ? '.' . $ext : '');
            $relativePath = 'uploads/departments/' . $departmentKey . '/' . $storedName;
            $uploadDir = __DIR__ . '/uploads/departments/' . $departmentKey . '/';

            if (!is_dir($uploadDir) && !mkdir($uploadDir, 0777, true)) {
                $uploadError = '업로드 폴더를 준비하지 못했습니다. 경로: ' . $uploadDir;
            } elseif (!is_writable($uploadDir)) {
                $uploadError = '업로드 폴더에 쓸 수 없습니다. 경로: ' . $uploadDir;
            } else {
                $filePath = $uploadDir . $storedName;

                if (!move_uploaded_file($fileTmp, $filePath)) {
                    $uploadError = '파일 저장 중 오류가 발생했습니다. 저장 경로: ' . $filePath;
                } else {
                    $relatedType = 'DEPARTMENT';
                    $insertSql = "INSERT INTO attachments (related_type, related_id, title, uploader_id, original_name, stored_name, file_path, content_type, file_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                    $stmt = $conn->prepare($insertSql);

                    if (!$stmt) {
                        if (file_exists($filePath)) {
                            unlink($filePath);
                        }
                        $uploadError = '자료 등록 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error . ' / 저장 경로: ' . $filePath;
                    } else {
                        $stmt->bind_param('sisissssi', $relatedType, $departmentId, $resourceTitle, $uploaderId, $originalName, $storedName, $relativePath, $contentType, $fileSize);

                        if ($stmt->execute()) {
                            $uploadedUrl = 'uploads/departments/' . $departmentKey . '/' . $storedName;
                            $uploadMessage = '자료가 업로드되었습니다. 접근 경로: ' . $uploadedUrl;
                        } else {
                            if (file_exists($filePath)) {
                                unlink($filePath);
                            }
                            $uploadError = '자료 등록 중 시스템 오류가 발생했습니다. DB 오류: ' . $stmt->error . ' / 저장 경로: ' . $filePath;
                        }

                        $stmt->close();
                    }
                }
            }
        }
    }
}

$resources = [];
$resourceError = '';
$resourceSql = "SELECT a.attachment_id, a.title, a.original_name, a.file_size, a.created_at, e.name AS uploader_name FROM attachments a LEFT JOIN employees e ON a.uploader_id = e.employee_id WHERE a.related_type = 'DEPARTMENT' AND a.related_id = $departmentId AND (a.title LIKE '%$keyword%' OR a.original_name LIKE '%$keyword%') ORDER BY a.created_at DESC, a.attachment_id DESC";
$resourceResult = $conn->query($resourceSql);

if ($resourceResult) {
    while ($row = $resourceResult->fetch_assoc()) {
        $resources[] = $row;
    }
} else {
    $resourceError = '자료 검색 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error;
}

renderHeader(
    $department['name'] . ' 부서 자료',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $department['name'], 'href' => $department['file']],
        ['label' => '부서 자료'],
    ]
);
?>

<section class="page-hero">
    <h1><?= escape($department['name']) ?> 부서 자료</h1>
    <p>부서에서 사용하는 자료를 검색하거나 올릴 수 있습니다.</p>
</section>

<nav class="section-nav" aria-label="부서 상세 메뉴">
    <a href="<?= escape($department['file']) ?>">부서 개요</a>
    <a href="department_members.php?dept=<?= escape($departmentKey) ?>">구성원</a>
    <a href="department_teams.php?dept=<?= escape($departmentKey) ?>">소속 팀</a>
    <a class="current" aria-current="page" href="department_resources.php?dept=<?= escape($departmentKey) ?>">부서 자료</a>
</nav>

<div class="content-stack">
    <section class="panel">
        <div class="panel-header">
            <div>
                <h2>자료 검색</h2>
                <p class="panel-description">자료 제목으로 검색합니다.</p>
            </div>
            <span class="status-badge"><?= count($resources) ?>건</span>
        </div>
        <form class="form-row" method="get" action="department_resources.php">
            <input type="hidden" name="dept" value="<?= escape($departmentKey) ?>">
            <input type="search" name="keyword" value="<?= $keyword ?>" placeholder="자료 제목 검색" aria-label="자료 검색어">
            <button type="submit">검색</button>
        </form>
        <?php if ($keyword !== ''): ?>
            <p class="helper-text">검색어: <?= $keyword ?></p>
        <?php endif; ?>
        <?php if ($resourceError !== ''): ?>
            <div class="empty-state">
                <strong>자료를 불러오지 못했습니다.</strong>
                <?= escape($resourceError) ?>
            </div>
        <?php elseif (empty($resources)): ?>
            <div class="empty-state">
                <strong><?= $keyword !== '' ? '검색 결과가 없습니다.' : '등록된 부서 자료가 없습니다.' ?></strong>
                <?= $keyword !== '' ? '입력한 검색어와 일치하는 자료가 없습니다.' : '현재 등록된 자료가 없습니다.' ?>
            </div>
        <?php else: ?>
            <div class="table-wrap">
                <table>
                    <caption><?= escape($department['name']) ?> 부서 자료 검색 결과</caption>
                    <thead>
                        <tr>
                            <th scope="col">제목</th>
                            <th scope="col">파일명</th>
                            <th scope="col">등록자</th>
                            <th scope="col">크기</th>
                            <th scope="col">등록일</th>
                            <th scope="col">다운로드</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($resources as $resource): ?>
                            <tr>
                                <td><?= (string) ($resource['title'] ?: '제목 없음') ?></td>
                                <td><?= (string) $resource['original_name'] ?></td>
                                <td><?= escape((string) ($resource['uploader_name'] ?: '미확인')) ?></td>
                                <td><?= number_format((int) $resource['file_size']) ?> bytes</td>
                                <td><?= escape((string) $resource['created_at']) ?></td>
                                <td><a class="button secondary" href="download.php?id=<?= urlencode((string) $resource['attachment_id']) ?>">다운로드</a></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

    <section class="panel">
        <div class="panel-header">
            <div>
                <h2>자료 업로드</h2>
                <p class="panel-description">업무에 필요한 파일을 등록합니다.</p>
            </div>
            <span class="status-badge">준비 중</span>
        </div>

        <?php if ($uploadMessage !== ''): ?>
            <div class="empty-state">
                <strong>업로드가 완료되었습니다.</strong>
                <?= escape($uploadMessage) ?>
                <?php if ($uploadedUrl !== ''): ?>
                    <div><a class="button secondary" href="<?= escape($uploadedUrl) ?>" target="_blank" rel="noopener">파일 열기</a></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($uploadError !== ''): ?>
            <div class="empty-state">
                <strong>업로드하지 못했습니다.</strong>
                <?= escape($uploadError) ?>
            </div>
        <?php endif; ?>

        <?php if (false): ?>
            <div class="empty-state">
                <strong>업로드 기능은 준비 중입니다.</strong>
                현재는 파일이 저장되지 않습니다.
            </div>
        <?php else: ?>
            <form class="upload-box" method="post" enctype="multipart/form-data">
                <label for="resource-title">자료 제목</label>
                <input id="resource-title" type="text" name="title" placeholder="자료 제목 입력">
                <label for="resource-file">첨부파일</label>
                <input id="resource-file" type="file" name="resource_file">
                <p class="helper-text">파일 업로드 기능은 아직 준비 중입니다.</p>
                <button class="button" type="submit">업로드</button>
            </form>
        <?php endif; ?>
    </section>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    const uploadPanel = document.querySelector('.content-stack > .panel:nth-child(2)');
    if (!uploadPanel) {
        return;
    }

    const statusBadge = uploadPanel.querySelector('.status-badge');
    if (statusBadge) {
        statusBadge.textContent = '등록 가능';
    }

    const titleLabel = uploadPanel.querySelector('label[for="resource-title"]');
    if (titleLabel) {
        titleLabel.textContent = '자료 제목';
    }

    const titleInput = uploadPanel.querySelector('#resource-title');
    if (titleInput) {
        titleInput.setAttribute('placeholder', '자료 제목 입력');
    }

    const fileLabel = uploadPanel.querySelector('label[for="resource-file"]');
    if (fileLabel) {
        fileLabel.textContent = '첨부파일';
    }

    const helperText = uploadPanel.querySelector('.upload-box .helper-text');
    if (helperText) {
        helperText.textContent = '업무에 필요한 자료 파일을 등록합니다.';
    }

    const submitButton = uploadPanel.querySelector('.upload-box button[type="submit"]');
    if (submitButton) {
        submitButton.textContent = '업로드';
    }
});
</script>

<?php renderFooter(); ?>
