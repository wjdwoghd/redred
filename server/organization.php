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
    '조직도',
    [
        ['label' => '부서', 'href' => 'department.php'],
        ['label' => '조직도'],
    ]
);
?>

<section class="page-hero">
    <h1>조직도</h1>
    <p>Cortis의 부서 구성을 확인할 수 있습니다.</p>
</section>

<?php renderDepartmentSectionNav('organization'); ?>

<section class="panel organization" aria-labelledby="organization-title">
    <h2 id="organization-title" class="org-root">대표</h2>
    <div class="org-grid">
        <?php foreach ($department as $department): ?>
            <a class="org-node" href="<?= escape($department['file']) ?>">
                <?= escape($department['name']) ?> 부서
            </a>
        <?php endforeach; ?>
    </div>
</section>

<?php renderFooter(); ?>
