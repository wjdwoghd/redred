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

renderHeader('부서 안내', [['label' => '부서']]);
?>

<section class="page-hero">
    <h1>부서 안내</h1>
    <p>부서를 선택하면 해당 부서의 정보를 확인할 수 있습니다.</p>
</section>

<?php renderDepartmentSectionNav('list'); ?>

<section class="page-grid" aria-label="부서 목록">
    <?php foreach (array_values($department) as $index => $departmentItem): ?>
        <article class="department-card">
            <span class="number"><?= str_pad((string) ($index + 1), 2, '0', STR_PAD_LEFT) ?></span>
            <h2><?= escape($departmentItem['name']) ?></h2>
            <p><?= escape($departmentItem['summary']) ?></p>
            <a href="<?= escape($departmentItem['file']) ?>" aria-label="<?= escape($departmentItem['name']) ?> 부서 상세 보기">
                부서 상세 보기 →
            </a>
        </article>
    <?php endforeach; ?>
</section>

<?php renderFooter(); ?>
