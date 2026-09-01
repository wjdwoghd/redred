<?php

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
session_start();

require_once __DIR__ . '/../database/db.php';


/*
 * 로그인 여부 확인
 */

if (!isset($_SESSION["employee_id"])) {

    header("Location: login.php");
    exit;

}


/*
 * 현재 로그인한 사용자 정보 조회
 */

$employee_id = $_SESSION["employee_id"];

$sql = "
    SELECT
        e.employee_id,
        e.employee_number,
        e.name,
        e.email,
        e.phone,
        e.position,
        e.role,
        e.joined_date,
        d.department_name
    FROM employees e
    LEFT JOIN department d
        ON e.department_id = d.department_id
    WHERE e.employee_id = $employee_id
";

$result = $conn->query($sql);

if (!$result || $result->num_rows === 0) {

    die("사용자 정보를 찾을 수 없습니다.");

}

$user = $result->fetch_assoc();

?>

<!DOCTYPE html>
<html lang="ko">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>My Page - Cortis</title>


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


        .mypage-link {
            margin-left: auto;
            font-weight: bold;
            color: #2563eb;
        }


        /* Main */

        main {
            width: 1100px;
            margin: 35px auto;
        }


        /* Welcome */

        .welcome {
            background: white;
            padding: 35px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            margin-bottom: 25px;
        }

        .welcome h1 {
            margin-top: 0;
        }

        .welcome p {
            color: #666;
        }


        /* Grid */

        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
        }


        /* Card */

        .card {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        .card h2 {
            margin-top: 0;
            margin-bottom: 20px;
        }


        /* User Information */

        .user-info table {
            width: 100%;
            border-collapse: collapse;
        }

        .user-info th {
            width: 130px;
            text-align: left;
            padding: 12px;
            background: #f8fafc;
            border-bottom: 1px solid #e5e7eb;
        }

        .user-info td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }


        /* Notification */

        .notification-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .notification-list li {
            padding: 15px;
            margin-bottom: 10px;
            background: #f8fafc;
            border-radius: 6px;
            border-left: 4px solid #2563eb;
        }


        /* Logout */

        .logout {
            margin-top: 25px;
            text-align: right;
        }

        .logout a {
            display: inline-block;
            padding: 12px 20px;
            background: #dc2626;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }

        .logout a:hover {
            background: #b91c1c;
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

        <a href="index.php">홈</a>

        <a href="login.php">로그인</a>

        <a href="resource.php">자료실</a>

        <a href="department.php">부서</a>

        <a href="notices.php">공지사항</a>

        <a href="mypage.php" class="mypage-link active">
            My Page
        </a>

    </div>

</nav>


<!-- Main -->

<main>


    <!-- Welcome -->

    <section class="welcome">

        <h1>
            My Page
        </h1>

        <p>
            <?= htmlspecialchars($user["name"]) ?>님,
            안녕하세요.
        </p>

    </section>


    <!-- Content -->

    <section class="content-grid">


        <!-- User Information -->

        <div class="card user-info">

            <h2>내 정보</h2>

            <table>

                <tr>
                    <th>이름</th>
                    <td>
                        <?= htmlspecialchars($user["name"]) ?>
                    </td>
                </tr>

                <tr>
                    <th>사번</th>
                    <td>
                        <?= htmlspecialchars($user["employee_number"]) ?>
                    </td>
                </tr>

                <tr>
                    <th>이메일</th>
                    <td>
                        <?= htmlspecialchars($user["email"]) ?>
                    </td>
                </tr>

                <tr>
                    <th>전화번호</th>
                    <td>
                        <?= htmlspecialchars($user["phone"] ?? "-") ?>
                    </td>
                </tr>

                <tr>
                    <th>부서</th>
                    <td>
                        <?= htmlspecialchars($user["department_name"] ?? "-") ?>
                    </td>
                </tr>

                <tr>
                    <th>직급</th>
                    <td>
                        <?= htmlspecialchars($user["position"] ?? "-") ?>
                    </td>
                </tr>

                <tr>
                    <th>권한</th>
                    <td>
                        <?= htmlspecialchars($user["role"]) ?>
                    </td>
                </tr>

                <tr>
                    <th>입사일</th>
                    <td>
                        <?= htmlspecialchars($user["joined_date"] ?? "-") ?>
                    </td>
                </tr>

            </table>

        </div>


        <!-- Notification -->

        <div class="card">

            <h2>알림</h2>

            <ul class="notification-list">

                <li>
                    새로운 공지사항이 등록되었습니다.
                </li>

                <li>
                    시스템 정기 점검 일정이 등록되었습니다.
                </li>

                <li>
                    새로운 업무 알림이 있습니다.
                </li>

            </ul>

        </div>


    </section>


    <!-- Logout -->

    <div class="logout">

        <a href="logout.php">
            로그아웃
        </a>

    </div>


</main>


<!-- Footer -->

<footer>

    Cortis &copy; 2026

</footer>


</body>

</html>
