# GEMINI.md

# RightDone Intelligence

## Vision

Cílem projektu je vytvořit AI platformu pro OSINT, Due Diligence a
bezpečnostní analýzu.

Projekt není zaměřen na útočné aktivity.

Veškeré informace pochází z veřejných zdrojů nebo z autorizovaných
bezpečnostních auditů infrastruktury vlastněné zákazníkem.

AI musí vždy preferovat pasivní sběr dat před aktivním skenováním.

------------------------------------------------------------------------

# Local AI Development Policy

Tento projekt používá lokální LLM modely.

## Cíl

-   šetřit tokeny
-   minimalizovat cloud usage
-   mít kontrolu nad vývojem

## Používané modely

Lokální (Ollama)

-   coder → deepseek-coder
-   qwen → qwen2.5

Použití

-   coder → psaní kódu
-   qwen → vysvětlení, debugging, návrhy architektury

## Zásady

-   vždy preferuj lokální modely
-   cloud používej pouze pokud je to skutečně nutné
-   neplýtvej tokeny
-   nepoužívej velké modely na jednoduché úkoly

------------------------------------------------------------------------

# Long Term Goal

Vytvořit nejlepší AI Due Diligence platformu v Evropě.

Uživatel zadá například:

-   doménu
-   IČO
-   název firmy
-   osobu
-   IP adresu

Systém automaticky vytvoří kompletní profil subjektu.

------------------------------------------------------------------------

# Technology Stack

## Backend

-   PHP 8.4
-   MariaDB
-   Redis
-   Ubuntu 24
-   Docker

## Frontend

-   Bootstrap 5
-   Vanilla JavaScript
-   Chart.js
-   Cytoscape.js

------------------------------------------------------------------------

# Modules

## Company Intelligence

-   ARES
-   Obchodní rejstřík
-   Skuteční majitelé
-   Sbírka listin
-   Historie změn
-   Jednatelé
-   Společníci
-   Firemní graf

## Infrastructure Intelligence

-   WHOIS
-   DNS
-   ASN
-   IP rozsahy
-   SSL
-   Subdomény
-   robots.txt
-   sitemap.xml
-   Wayback Machine
-   Technologie webu

## Leak Intelligence

-   veřejně dostupné úniky
-   kompromitované e-maily z veřejných databází
-   GitHub
-   veřejně dostupné API klíče

## Vulnerability Intelligence

Pouze pro autorizované cíle.

Podporované nástroje:

-   Nmap
-   OpenVAS
-   Greenbone
-   Nikto

AI pouze analyzuje výsledky.

Nikdy nenavrhuje ani neprovádí exploitační kroky.

## Risk Engine

Každému nálezu přiřaď:

-   Critical
-   High
-   Medium
-   Low
-   Informational

## Graph Engine

Entity:

-   Firma
-   Osoba
-   Doména
-   IP
-   Certifikát
-   Email
-   Telefon
-   Adresa

Každá vazba musí být uložena.

## AI Report

Každý report obsahuje:

-   Executive Summary
-   Technický report
-   Timeline
-   Risk Score
-   Priority
-   Doporučení

------------------------------------------------------------------------

# Coding Rules

-   čisté objektové PHP
-   Dependency Injection
-   REST API
-   žádné míchání HTML a PHP
-   logovat všechny akce
-   zachytit všechny chyby

------------------------------------------------------------------------

# Development Workflow

1.  Architektura
2.  Databáze
3.  API
4.  Backend
5.  Frontend
6.  AI

Nikdy nezačínej implementovat bez návrhu.

------------------------------------------------------------------------

# Business Vision

RightDone Intelligence není OSINT nástroj.

Je to AI analytik.

Zákazník nechce data.

Zákazník chce rozhodnutí.

Například:

-   Mám podepsat smlouvu?
-   Jaké je obchodní riziko?
-   Je firma důvěryhodná?
-   Existují veřejně známé problémy?
-   Jaká doporučení z toho plynou?

Každá analýza musí skončit jasným závěrem.

------------------------------------------------------------------------

# Monetization

Model:

Pay Per Report.

Žádné předplatné.

Žádné měsíční licence.

Každý report je samostatný produkt.

Po zaplacení zůstává zákazníkovi dostupný minimálně 30 dní.

------------------------------------------------------------------------

# Free Report

Zdarma zobraz:

-   Executive Summary
-   AI Risk Score
-   základní informace
-   počet nalezených vazeb
-   počet veřejných dokumentů
-   počet nalezených rizik
-   počet nalezených technologií
-   počet analyzovaných veřejných zdrojů

Free report musí mít skutečnou hodnotu.

Nikdy nevytvářej umělé nálezy.

------------------------------------------------------------------------

# Premium Report

Obsahuje:

-   detail všech firemních vazeb
-   detail osob
-   detail dokumentů
-   časovou osu
-   graf vztahů
-   detail rizik
-   detail bezpečnostních zjištění
-   AI doporučení
-   PDF export

------------------------------------------------------------------------

# Report Philosophy

Nezamykej celý report.

Zdarma ukaž nejdůležitější informace.

Placená verze přidává hloubku.

Cíl:

"Tento report mi už pomohl.

Chci vědět víc."

------------------------------------------------------------------------

# User Experience

První stránka obsahuje:

-   Risk Score
-   Executive Summary
-   počet analyzovaných zdrojů
-   počet nalezených objektů
-   počet nalezených rizik
-   počet nalezených vazeb

------------------------------------------------------------------------

# AI Philosophy

AI není vyhledávač.

AI je analytik.

Každý report musí odpovědět:

-   Co bylo nalezeno?
-   Jak závažné to je?
-   Jaké z toho plyne riziko?
-   Co doporučit?

Každý závěr musí být podložen nalezenými daty.

AI nikdy nesmí vytvářet nepodložené závěry.

------------------------------------------------------------------------

# Golden Rule

Každá nová funkce musí odpovědět na otázku:

Pomůže tato funkce zákazníkovi udělat lepší rozhodnutí?

Pokud ne, nebude implementována.

------------------------------------------------------------------------

# Ultimate Goal

Jedno vstupní pole.

Jedno tlačítko.

Jedna jasná odpověď.

To je RightDone Intelligence.

