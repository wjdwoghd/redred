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

$departmentKey = $_GET['dept'] ?? '';

if (!isset($department[$departmentKey])) {
    http_response_code(404);
    exit('부서 정보를 찾을 수 없습니다.');
}

$department = $department[$departmentKey];

renderHeader(
    '구성원 상세',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $department['name'], 'href' => $department['file']],
        ['label' => '구성원', 'href' => 'department_members.php?dept=' . $departmentKey],
        ['label' => '상세'],
    ]
);
?>

<section class="page-hero">
    <h1>구성원 상세</h1>
    <p>구성원의 기본 정보를 확인합니다.</p>
</section>

<div class="section-nav">
    <a href="department_members.php?dept=<?= escape($departmentKey) ?>">← 구성원 목록</a>
</div>

<section class="panel">
    <dl class="detail-list">
        <dt>이름</dt><dd>-</dd>
        <dt>직급</dt><dd>-</dd>
        <dt>부서</dt><dd><?= escape($department['name']) ?></dd>
        <dt>사내 이메일</dt><dd>-</dd>
        <dt>연락처</dt><dd>-</dd>
    </dl>
</section>

<?php renderFooter(); ?>
