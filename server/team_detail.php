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
    '팀 상세',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $department['name'], 'href' => $department['file']],
        ['label' => '소속 팀', 'href' => 'department_teams.php?dept=' . $departmentKey],
        ['label' => '상세'],
    ]
);
?>

<section class="page-hero">
    <h1>팀 상세</h1>
    <p>팀의 기본 정보와 구성원을 확인합니다.</p>
</section>

<div class="section-nav">
    <a href="department_teams.php?dept=<?= escape($departmentKey) ?>">← 팀 목록</a>
</div>

<section class="panel">
    <dl class="detail-list">
        <dt>팀명</dt><dd>-</dd>
        <dt>소속 부서</dt><dd><?= escape($department['name']) ?></dd>
        <dt>팀 소개</dt><dd>-</dd>
        <dt>구성원</dt><dd>-</dd>
    </dl>
</section>

<?php renderFooter(); ?>
