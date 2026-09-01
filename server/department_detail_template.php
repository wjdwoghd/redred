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

$departments = $department;

if (!isset($departmentKey, $departments[$departmentKey])) {
    http_response_code(404);
    exit('부서 정보를 찾을 수 없습니다.');
}

$currentDepartment = $departments[$departmentKey];
$departmentKeys = array_keys($departments);
$currentIndex = array_search($departmentKey, $departmentKeys, true);
$previousKey = $currentIndex > 0 ? $departmentKeys[$currentIndex - 1] : null;
$nextKey = $currentIndex < count($departmentKeys) - 1 ? $departmentKeys[$currentIndex + 1] : null;

renderHeader(
    $currentDepartment['name'] . ' 부서',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $currentDepartment['name']],
    ]
);
?>

<section class="page-hero">
    <h1><?= escape($currentDepartment['name']) ?> 부서</h1>
    <p><?= escape($currentDepartment['summary']) ?></p>
</section>

<nav class="section-nav" aria-label="부서 상세 메뉴">
    <a href="#overview">부서 개요</a>
    <a href="#duties">주요 업무</a>
    <a href="department_teams.php?dept=<?= escape($departmentKey) ?>">소속 팀</a>
    <a href="department_members.php?dept=<?= escape($departmentKey) ?>">구성원</a>
    <a href="department_resources.php?dept=<?= escape($departmentKey) ?>">부서 자료</a>
</nav>

<div class="content-stack">
    <section class="panel" id="overview">
        <div class="panel-header">
            <div>
                <h2>부서 개요</h2>
                <p class="panel-description">부서의 기본 정보를 확인합니다.</p>
            </div>
            <span class="status-badge">준비 중</span>
        </div>
        <div class="empty-state">
            <strong>등록된 부서 소개가 없습니다.</strong>
            부서 소개가 아직 작성되지 않았습니다.
        </div>
    </section>

    <section class="panel" id="duties">
        <div class="panel-header">
            <div>
                <h2>주요 업무</h2>
                <p class="panel-description">부서에서 담당하는 업무입니다.</p>
            </div>
            <span class="status-badge">0건</span>
        </div>
        <div class="empty-state">
            <strong>등록된 주요 업무가 없습니다.</strong>
            등록된 업무가 없습니다.
        </div>
    </section>

    <section class="panel" id="teams">
        <div class="panel-header">
            <div>
                <h2>소속 팀</h2>
                <p class="panel-description">부서에 소속된 팀을 확인합니다.</p>
            </div>
            <span class="status-badge">0개 팀</span>
        </div>
        <div class="empty-state">
            <strong>등록된 팀 정보가 없습니다.</strong>
            등록된 팀이 없습니다.
            <div class="empty-actions">
                <a class="button secondary" href="department_teams.php?dept=<?= escape($departmentKey) ?>">팀 페이지 보기</a>
            </div>
        </div>
    </section>

    <section class="panel" id="members">
        <div class="panel-header">
            <div>
                <h2>구성원</h2>
                <p class="panel-description">부서 구성원을 확인합니다.</p>
            </div>
            <span class="status-badge">0명</span>
        </div>
        <div class="table-wrap">
            <table>
                <caption><?= escape($currentDepartment['name']) ?> 부서 구성원 목록</caption>
                <thead>
                    <tr>
                        <th scope="col">직급</th>
                        <th scope="col">이름</th>
                        <th scope="col">사내 이메일</th>
                        <th scope="col">연락처</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="4" class="empty-cell">등록된 구성원 정보가 없습니다.</td>
                    </tr>
                </tbody>
            </table>
        </div>
        <div class="empty-actions">
            <a class="button secondary" href="department_members.php?dept=<?= escape($departmentKey) ?>">구성원 페이지 보기</a>
        </div>
    </section>

    <section class="panel" id="resources">
        <div class="panel-header">
            <div>
                <h2>부서 자료</h2>
                <p class="panel-description">부서에서 공유하는 자료를 확인합니다.</p>
            </div>
            <span class="status-badge">0건</span>
        </div>
        <div class="empty-state">
            <strong>등록된 부서 자료가 없습니다.</strong>
            등록된 자료가 없습니다.
            <div class="empty-actions">
                <a class="button secondary" href="department_resources.php?dept=<?= escape($departmentKey) ?>">자료 페이지 보기</a>
            </div>
        </div>
    </section>
</div>

<nav class="page-actions" aria-label="부서 간 이동">
    <?php if ($previousKey !== null): ?>
        <a class="action-link" href="<?= escape($departments[$previousKey]['file']) ?>">
            ← 이전 부서 · <?= escape($departments[$previousKey]['name']) ?>
        </a>
    <?php else: ?>
        <a class="action-link" href="department.php">← 부서 목록</a>
    <?php endif; ?>

    <?php if ($nextKey !== null): ?>
        <a class="action-link next" href="<?= escape($departments[$nextKey]['file']) ?>">
            다음 부서 · <?= escape($departments[$nextKey]['name']) ?> →
        </a>
    <?php else: ?>
        <a class="action-link next" href="department.php">부서 목록 →</a>
    <?php endif; ?>
</nav>

<?php renderFooter(); ?>
