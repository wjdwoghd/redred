<?php

declare(strict_types=1);

$department = [
    'hr' => [
        'name' => '인사',
        'file' => 'department_hr.php',
        'summary' => '인사 부서의 조직과 구성원 정보를 확인합니다.',
    ],
    'administration' => [
        'name' => '행정',
        'file' => 'department_administration.php',
        'summary' => '행정 부서의 조직과 구성원 정보를 확인합니다.',
    ],
    'finance' => [
        'name' => '재무',
        'file' => 'department_finance.php',
        'summary' => '재무 부서의 조직과 구성원 정보를 확인합니다.',
    ],
    'planning' => [
        'name' => '기획',
        'file' => 'department_planning.php',
        'summary' => '기획 부서의 조직과 구성원 정보를 확인합니다.',
    ],
    'design' => [
        'name' => '디자인',
        'file' => 'department_design.php',
        'summary' => '디자인 부서의 조직과 구성원 정보를 확인합니다.',
    ],
    'sales' => [
        'name' => '영업',
        'file' => 'department_sales.php',
        'summary' => '영업 부서의 조직과 구성원 정보를 확인합니다.',
    ],
];

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
