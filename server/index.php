<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();
?>

<!DOCTYPE html>
<html lang="ko">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Cortis Company Portal</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, "Malgun Gothic", sans-serif;
            background: #f4f6f8;
            color: #333;
        }

        /* Header */

        header {
            background: #1f2937;
            color: white;
            padding: 22px 0;
        }

        .header-inner {
            width: 1100px;
            margin: auto;
        }

        .logo {
            font-size: 28px;
            font-weight: bold;
        }

        .subtitle {
            margin-top: 5px;
            font-size: 14px;
            color: #d1d5db;
        }

        /* Navigation */

        nav {
            background: white;
            border-bottom: 1px solid #ddd;
        }

        .nav-inner {
            width: 1100px;
            margin: auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .main-menu {
            display: flex;
            align-items: center;
        }

        nav a {
            display: block;
            padding: 18px 30px;
            color: #333;
            text-decoration: none;
            font-size: 15px;
        }

        nav a:hover {
            background: #f1f5f9;
        }

        nav a.active {
            color: #2563eb;
            font-weight: bold;
            border-bottom: 3px solid #2563eb;
        }

        /* My Page */

        .mypage-menu {
            margin-left: auto;
        }

        .mypage-menu a {
            font-weight: bold;
            color: #2563eb;
        }

        /* Main */

        main {
            width: 1100px;
            margin: 35px auto;
        }

        .welcome {
            background: white;
            padding: 35px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            margin-bottom: 25px;
        }

        .welcome h2 {
            margin-top: 0;
        }

        .welcome p {
            color: #666;
            line-height: 1.7;
        }

        .login-status {
            margin-top: 20px;
            padding: 15px;
            background: #f8fafc;
            border-radius: 6px;
            line-height: 2;
        }

        .login-status strong {
            color: #2563eb;
        }

        /* Menu */

        .menu-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        .card {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        .card h3 {
            margin-top: 0;
            font-size: 20px;
        }

        .card p {
            color: #666;
            line-height: 1.6;
        }

        .card a {
            color: #2563eb;
            text-decoration: none;
            font-weight: bold;
        }

        .card a:hover {
            text-decoration: underline;
        }

        /* Company Information */

        .company-info {
            background: white;
            margin-top: 30px;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        .company-info h2 {
            margin-top: 0;
            margin-bottom: 20px;
        }

        .company-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .company-info th {
            width: 150px;
            text-align: left;
            padding: 12px;
            background: #f8fafc;
            border-bottom: 1px solid #e5e7eb;
        }

        .company-info td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }

        .company-info a {
            color: #2563eb;
            text-decoration: none;
        }

        /* Footer */

        footer {
            margin-top: 60px;
            background: #1f2937;
            color: #aaa;
            text-align: center;
            padding: 25px;
            font-size: 13px;
        }

    </style>
    <link rel="stylesheet" href="logo.css">

</head>

<body>


<!-- Header -->

<header>

    <div class="header-inner">

        <a class="cortis-logo-link" href="index.php" aria-label="Cortis 홈">
            <img class="cortis-logo-image" src="Cortis_로고.png" alt="Cortis">
        </a>

        <div class="subtitle">
            Company Internal Management System
        </div>

    </div>

</header>


<!-- Navigation -->

<nav>

    <div class="nav-inner">

        <div class="main-menu">

            <a href="index.php" class="active">홈</a>

            <a href="login.php">로그인</a>

            <a href="resource.php">자료실</a>

            <a href="department.php">부서</a>

            <a href="notices.php">공지사항</a>

        </div>


        <!-- My Page -->

        <div class="mypage-menu">

            <?php if (isset($_SESSION["employee_id"])): ?>

                <a href="mypage.php">
                    My Page
                </a>

            <?php else: ?>

                <a href="login.php">
                    Login
                </a>

            <?php endif; ?>

        </div>

    </div>

</nav>


<!-- Main -->

<main>


    <!-- Welcome -->

    <section class="welcome">

        <?php if (isset($_SESSION["employee_id"])): ?>

            <h2>
                Welcome,
                <?= htmlspecialchars($_SESSION["name"] ?? "사용자") ?>.
            </h2>

            <p>
                Cortis Company Portal에 로그인하셨습니다.
            </p>

            <div class="login-status">

                현재 로그인 계정 :
                <strong>
                    <?= htmlspecialchars($_SESSION["employee_number"] ?? "") ?>
                </strong>

                <br>

                권한 :
                <strong>
                    <?= htmlspecialchars($_SESSION["role"] ?? "USER") ?>
                </strong>

            </div>

        <?php else: ?>

            <h2>
                Welcome to Cortis.
            </h2>

            <p>
                Cortis 임직원을 위한 사내 업무 포털입니다.
                회사의 공지사항, 부서 정보, 자료실 및
                다양한 사내 업무 서비스를 이용할 수 있습니다.
            </p>

        <?php endif; ?>

    </section>


    <!-- Menu -->

    <section class="menu-grid">


        <!-- Login -->

        <div class="card">

            <h3>로그인</h3>

            <p>
                임직원 계정으로 로그인하여
                사내 서비스를 이용할 수 있습니다.
            </p>

            <a href="login.php">
                로그인 →
            </a>

        </div>


        <!-- 자료실 -->

        <div class="card">

            <h3>자료실</h3>

            <p>
                업무에 필요한 자료와 문서를
                업로드하고 확인할 수 있습니다.
            </p>

            <a href="resource.php">
                자료실 →
            </a>

        </div>


        <!-- 부서 -->

        <div class="card">

            <h3>부서</h3>

            <p>
                회사의 부서 및 임직원 정보를
                확인할 수 있습니다.
            </p>

            <a href="department.php">
                부서 정보 →
            </a>

        </div>


        <!-- 공지사항 -->

        <div class="card">

            <h3>공지사항</h3>

            <p>
                회사의 주요 공지사항과
                시스템 관련 안내를 확인할 수 있습니다.
            </p>

            <a href="notices.php">
                공지사항 →
            </a>

        </div>


    </section>


    <!-- Company Information -->

    <section class="company-info">

        <h2>회사 소개</h2>

        <table>

            <tr>
                <th>회사명</th>
                <td>Cortis</td>
            </tr>

            <tr>
                <th>대표</th>
                <td>고티스</td>
            </tr>

            <tr>
                <th>주소</th>
                <td>서울시 충무로</td>
            </tr>

            <tr>
                <th>대표 이메일</th>
                <td>
                    <a href="mailto:cortis@admin.com">
                        cortis@admin.com
                    </a>
                </td>
            </tr>

        </table>

    </section>


</main>


<!-- Footer -->

<footer>

    Cortis &copy; 2026

</footer>


</body>

</html>
