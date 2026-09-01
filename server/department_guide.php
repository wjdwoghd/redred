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

renderHeader(
    '부서별 담당 업무',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => '담당 업무'],
    ]
);
?>

<section class="page-hero">
    <h1>부서별 담당 업무</h1>
    <p>각 부서가 맡고 있는 업무를 확인할 수 있습니다.</p>
</section>

<?php renderDepartmentSectionNav('guide'); ?>

<section class="panel">
    <div class="panel-header">
        <div>
            <h2>담당 업무 안내</h2>
            <p class="panel-description">부서별 업무 범위를 정리하는 화면입니다.</p>
        </div>
        <span class="status-badge">0건</span>
    </div>

    <div class="table-wrap">
        <table>
            <caption>부서별 담당 업무 목록</caption>
            <thead>
                <tr>
                    <th scope="col">부서</th>
                    <th scope="col">담당 업무</th>
                    <th scope="col">바로가기</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td colspan="3" class="empty-cell">등록된 담당 업무가 없습니다.</td>
                </tr>
            </tbody>
        </table>
    </div>
</section>

<?php renderFooter(); ?>
