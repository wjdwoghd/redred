<?php

declare(strict_types=1);

function renderHeader(string $title, array $breadcrumbs = []): void
{
    ?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Cortis 사내 포털 부서 안내">
    <title><?= escape($title) ?> | Cortis</title>
    <style>
        :root{--navy:#1f2937;--blue:#2563eb;--blue-light:#eff6ff;--text:#111827;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--white:#fff;--shadow:0 12px 30px rgba(15,23,42,.07)}
        *{box-sizing:border-box}html{scroll-behavior:smooth}body{min-height:100vh;margin:0;display:flex;flex-direction:column;font-family:Arial,"Malgun Gothic",sans-serif;background:#f4f6f8;color:var(--text)}a{color:inherit}
        .site-header{padding:22px 0;background:var(--navy);color:var(--white)}.container{width:1100px;max-width:calc(100% - 40px);margin:0 auto}.brand{display:inline-block;color:var(--white);font-size:28px;font-weight:700;letter-spacing:-.02em;text-decoration:none}.subtitle{margin-top:5px;color:#d1d5db;font-size:14px}
        .site-nav{background:var(--white);border-bottom:1px solid var(--line)}.nav-inner{display:flex;align-items:center;flex-wrap:wrap}.site-nav a{display:block;padding:17px 22px;color:#334155;border-bottom:3px solid transparent;font-size:15px;text-decoration:none}.site-nav a:hover,.site-nav a:focus-visible{background:var(--soft);color:var(--blue)}.site-nav a.active{border-bottom-color:var(--blue);color:var(--blue);font-weight:700}:focus-visible{outline:3px solid rgba(37,99,235,.3);outline-offset:3px}
        main{flex:1;padding:34px 0 64px}.breadcrumb{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:18px;color:var(--muted);font-size:14px}.breadcrumb a{color:var(--blue);text-decoration:none}
        .page-hero,.panel{background:var(--white);border:1px solid rgba(226,232,240,.9);border-radius:12px;box-shadow:var(--shadow)}.page-hero{position:relative;padding:34px;overflow:hidden}.page-hero:after{position:absolute;top:0;right:0;width:120px;height:5px;background:var(--blue);content:""}.page-hero h1{margin:0;font-size:clamp(28px,4vw,38px);letter-spacing:-.04em}.page-hero p{max-width:680px;margin:13px 0 0;color:#475569;line-height:1.7}
        .section-nav{display:flex;gap:8px;margin:18px 0 24px;padding:8px;overflow-x:auto;background:var(--white);border:1px solid var(--line);border-radius:10px}.section-nav a{flex:0 0 auto;padding:10px 14px;color:#475569;border-radius:7px;font-size:14px;font-weight:700;text-decoration:none}.section-nav a:hover,.section-nav a:focus-visible,.section-nav a.current{background:var(--blue-light);color:var(--blue)}
        .page-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-top:24px}.department-card{position:relative;min-height:190px;padding:25px;background:var(--white);border:1px solid var(--line);border-radius:12px;box-shadow:0 4px 18px rgba(15,23,42,.04);transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease}.department-card:hover,.department-card:focus-within{transform:translateY(-3px);border-color:#93c5fd;box-shadow:var(--shadow)}.department-card .number{color:#cbd5e1;font-size:13px;font-weight:700}.department-card h2{margin:18px 0 9px;font-size:22px}.department-card p{margin:0 0 20px;color:#475569;font-size:14px;line-height:1.65}.department-card a{color:var(--blue);font-size:14px;font-weight:700;text-decoration:none}.department-card a:after{position:absolute;inset:0;content:""}
        
        .content-stack{display:grid;gap:18px}.panel{padding:28px;scroll-margin-top:20px}.panel-header{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:18px}.panel h2{margin:0;font-size:21px}.panel-description{margin:6px 0 0;color:var(--muted);font-size:14px}.status-badge{flex:0 0 auto;padding:6px 10px;background:#f1f5f9;color:#475569;border-radius:999px;font-size:12px;font-weight:700}.empty-state{padding:42px 24px;background:var(--soft);color:var(--muted);border:1px dashed #cbd5e1;border-radius:9px;text-align:center}.empty-state strong{display:block;margin-bottom:6px;color:#334155;font-size:15px}
        .table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:9px}table{width:100%;min-width:650px;border-collapse:collapse}caption{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}th,td{padding:15px 17px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}th{background:var(--soft);color:#334155}tbody tr:last-child td{border-bottom:0}.empty-cell{padding:42px 18px;color:var(--muted);text-align:center}
        .page-actions{display:flex;align-items:stretch;justify-content:space-between;gap:14px;margin-top:24px}.action-link{flex:1;padding:16px 18px;background:var(--white);color:#334155;border:1px solid var(--line);border-radius:9px;font-size:14px;text-decoration:none}.action-link.next{text-align:right}.action-link:hover,.action-link:focus-visible{border-color:#93c5fd;color:var(--blue)}
        .organization{margin-top:24px;padding:34px}.org-root{display:inline-block;margin:0 0 18px;padding:8px 13px;background:var(--blue-light);color:var(--blue);border:1px solid #bfdbfe;border-radius:999px;font-size:14px;font-weight:700}.org-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.org-node{display:block;padding:20px;background:var(--soft);color:#334155;border:1px solid var(--line);border-radius:9px;text-align:center;font-weight:700;text-decoration:none}.org-node:hover,.org-node:focus-visible{background:var(--blue-light);color:var(--blue);border-color:#93c5fd}
        .form-row{display:flex;gap:10px;margin-bottom:18px}.form-row input,.form-row select,.upload-box input{width:100%;padding:12px 14px;background:var(--white);border:1px solid #cbd5e1;border-radius:8px;font:inherit}.form-row button,.button{flex:0 0 auto;padding:12px 18px;background:var(--blue);color:var(--white);border:0;border-radius:8px;font-size:14px;font-weight:700;text-decoration:none;cursor:pointer}.form-row button:hover,.button:hover{background:#1d4ed8}.button.secondary{background:var(--white);color:#334155;border:1px solid var(--line)}.empty-actions{display:flex;justify-content:center;gap:10px;margin-top:18px}.upload-box{display:grid;gap:12px;padding:22px;background:var(--soft);border:1px dashed #cbd5e1;border-radius:9px}.upload-box label{font-size:14px;font-weight:700}.helper-text{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.detail-list{display:grid;grid-template-columns:160px 1fr;margin:0;border-top:1px solid var(--line)}.detail-list dt,.detail-list dd{margin:0;padding:15px;border-bottom:1px solid var(--line)}.detail-list dt{background:var(--soft);font-weight:700}.site-footer{padding:25px;background:var(--navy);color:#9ca3af;text-align:center;font-size:13px}
        @media(max-width:800px){.page-grid,.org-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){.container{max-width:calc(100% - 28px)}.site-nav .container{max-width:100%}.site-nav a{flex:1 0 33.333%;padding:13px 8px;text-align:center;font-size:13px}main{padding-top:24px}.page-hero,.panel,.organization{padding:22px}.page-grid,.org-grid{grid-template-columns:1fr}.page-actions,.form-row{flex-direction:column}.action-link.next{text-align:left}.detail-list{grid-template-columns:1fr}.detail-list dt{padding-bottom:6px;border-bottom:0}.detail-list dd{padding-top:6px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}.department-card{transition:none}}
    </style>
    <link rel="stylesheet" href="logo.css">
</head>
<body>
<header class="site-header">
    <div class="container">
        <a class="brand cortis-logo-link" href="index.php" aria-label="Cortis 홈">
            <img class="cortis-logo-image" src="Cortis_로고.png" alt="Cortis">
        </a>
        <div class="subtitle">Company Internal Management System</div>
    </div>
</header>
<nav class="site-nav" aria-label="주요 메뉴">
    <div class="container nav-inner">
        <a href="index.php">홈</a>
        <a href="login.php">로그인</a>
        <a href="resource.php">자료실</a>
        <a href="department.php" class="active" aria-current="page">부서</a>
        <a href="notices.php">공지사항</a>
    </div>
</nav>
<main>
    <div class="container">
        <?php if ($breadcrumbs !== []): ?>
            <nav class="breadcrumb" aria-label="현재 위치">
                <a href="index.php">홈</a>
                <span aria-hidden="true">›</span>
                <?php foreach ($breadcrumbs as $index => $breadcrumb): ?>
                    <?php if ($index > 0): ?><span aria-hidden="true">›</span><?php endif; ?>
                    <?php if (isset($breadcrumb['href'])): ?>
                        <a href="<?= escape($breadcrumb['href']) ?>"><?= escape($breadcrumb['label']) ?></a>
                    <?php else: ?>
                        <span aria-current="page"><?= escape($breadcrumb['label']) ?></span>
                    <?php endif; ?>
                <?php endforeach; ?>
            </nav>
        <?php endif; ?>
    <?php
}

function renderDepartmentSectionNav(string $current): void
{
    $items = [
        'list' => ['label' => '부서 목록', 'href' => 'department.php'],
        'organization' => ['label' => '조직도', 'href' => 'organization.php'],
        'guide' => ['label' => '담당 업무', 'href' => 'department_guide.php'],
    ];
    ?>
    <nav class="section-nav" aria-label="부서 메뉴">
        <?php foreach ($items as $key => $item): ?>
            <a href="<?= escape($item['href']) ?>"<?= $key === $current ? ' class="current" aria-current="page"' : '' ?>>
                <?= escape($item['label']) ?>
            </a>
        <?php endforeach; ?>
    </nav>
    <?php
}

function renderFooter(): void
{
    ?>
    </div>
</main>
<footer class="site-footer">Cortis &copy; 2026</footer>
</body>
</html>
    <?php
}
