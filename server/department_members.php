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
$departmentName = $department['name'];
$keyword = trim(($_GET['keyword'] ?? ''));
$members = [];
$memberError = '';
$memberSql = "SELECT e.employee_id, e.position, e.name, e.email, e.phone FROM employees e LEFT JOIN department d ON e.department_id = d.department_id WHERE d.department_name = '$departmentName' AND (e.name LIKE '%$keyword%' OR e.position LIKE '%$keyword%') ORDER BY e.employee_id ASC";
$memberResult = $conn->query($memberSql);

if ($memberResult) {
    while ($row = $memberResult->fetch_assoc()) {
        $members[] = $row;
    }
} else {
    $memberError = '구성원 검색 중 시스템 오류가 발생했습니다. DB 오류: ' . $conn->error;
}

renderHeader(
    $department['name'] . ' 부서 구성원',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => $department['name'], 'href' => $department['file']],
        ['label' => '구성원'],
    ]
);
?>

<section class="page-hero">
    <h1><?= escape($department['name']) ?> 부서 구성원</h1>
    <p>부서 구성원을 검색할 수 있습니다.</p>
</section>

<nav class="section-nav" aria-label="부서 상세 메뉴">
    <a href="<?= escape($department['file']) ?>">부서 개요</a>
    <a class="current" aria-current="page" href="department_members.php?dept=<?= escape($departmentKey) ?>">구성원</a>
    <a href="department_teams.php?dept=<?= escape($departmentKey) ?>">소속 팀</a>
    <a href="department_resources.php?dept=<?= escape($departmentKey) ?>">부서 자료</a>
</nav>

<section class="panel">
    <form class="form-row" method="get" action="department_members.php">
        <input type="hidden" name="dept" value="<?= escape($departmentKey) ?>">
        <input type="search" name="keyword" value="<?= $keyword ?>" placeholder="이름 또는 직급 검색" aria-label="구성원 검색어">
        <button type="submit">검색</button>
    </form>
    <?php if ($keyword !== ''): ?>
        <p class="helper-text">검색어: <?= $keyword ?></p>
    <?php endif; ?>

    <div class="table-wrap">
        <table>
            <caption><?= escape($department['name']) ?> 부서 구성원 검색 결과</caption>
            <thead>
                <tr>
                    <th scope="col">직급</th>
                    <th scope="col">이름</th>
                    <th scope="col">사내 이메일</th>
                    <th scope="col">연락처</th>
                    <th scope="col">상세</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($memberError !== ''): ?>
                    <tr>
                        <td colspan="5" class="empty-cell"><?= escape($memberError) ?></td>
                    </tr>
                <?php elseif (empty($members)): ?>
                    <tr>
                        <td colspan="5" class="empty-cell">
                            <?= $keyword !== '' ? '“' . $keyword . '” 검색 결과가 없습니다.' : '등록된 구성원 정보가 없습니다.' ?>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($members as $member): ?>
                        <tr>
                            <td><?= escape((string) $member['position']) ?></td>
                            <td><?= escape((string) $member['name']) ?></td>
                            <td><?= escape((string) $member['email']) ?></td>
                            <td><?= escape((string) $member['phone']) ?></td>
                            <td><a class="button secondary" href="member_detail.php?dept=<?= escape($departmentKey) ?>">상세</a></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="empty-actions">
        <a class="button secondary" href="member_detail.php?dept=<?= escape($departmentKey) ?>">상세 페이지 보기</a>
    </div>
</section>

<?php renderFooter(); ?>
