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
    $department['name'] . ' 부서 소속 팀',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $department['name'], 'href' => $department['file']],
        ['label' => '소속 팀'],
    ]
);
?>

<section class="page-hero">
    <h1><?= escape($department['name']) ?> 부서 소속 팀</h1>
    <p>부서에 소속된 팀을 확인할 수 있습니다.</p>
</section>

<nav class="section-nav" aria-label="부서 상세 메뉴">
    <a href="<?= escape($department['file']) ?>">부서 개요</a>
    <a href="department_members.php?dept=<?= escape($departmentKey) ?>">구성원</a>
    <a class="current" aria-current="page" href="department_teams.php?dept=<?= escape($departmentKey) ?>">소속 팀</a>
    <a href="department_resources.php?dept=<?= escape($departmentKey) ?>">부서 자료</a>
</nav>

<section class="panel">
    <div class="panel-header">
        <div>
            <h2>팀 목록</h2>
            <p class="panel-description">부서에 소속된 팀 목록입니다.</p>
        </div>
        <span class="status-badge">0개 팀</span>
    </div>
    <div class="empty-state">
        <strong>등록된 팀 정보가 없습니다.</strong>
        현재 등록된 팀이 없습니다.
        <div class="empty-actions">
            <a class="button secondary" href="team_detail.php?dept=<?= escape($departmentKey) ?>">상세 페이지 보기</a>
        </div>
    </div>
</section>

<?php renderFooter(); ?>
