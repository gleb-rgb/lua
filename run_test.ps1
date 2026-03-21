$file = "anonymizer_spec.lua"
$lines = Get-Content $file -Encoding UTF8

$testDictionary = @{}

$cleanMenu = @()

foreach ($line in $lines) {
    if ($line -match 'describe\s*\(\s*"([^"]*?)\s*#([a-zA-Z0-9_]+)[^"]*"') {
        $cleanName = "📦 ГРУППА: " + $matches[1].Trim() 
        $tag = $matches[2]
        
        $testDictionary[$cleanName] = $tag
        $cleanMenu += $cleanName
    }

    elseif ($line -match 'it\s*\(\s*"([^"]*?)\s*#([a-zA-Z0-9_]+)[^"]*"') {
        $cleanName = "   🧪 ТЕСТ: " + $matches[1].Trim()
        $tag = $matches[2]
        
        $testDictionary[$cleanName] = $tag
        $cleanMenu += $cleanName
    }
}

if ($cleanMenu.Count -eq 0) {
    Write-Host "Ни одного теста с маячком не найдено! Проверь файл." -ForegroundColor Red
    exit
}

$selected = $cleanMenu | Out-GridView -Title "🎯 Выбери тест" -PassThru

if ($selected) {
    $hiddenTag = $testDictionary[$selected]
    
    if ($hiddenTag) {
        Write-Host "Выбрано: $selected" -ForegroundColor Cyan
        Write-Host "Маячок найден: $hiddenTag" -ForegroundColor Magenta
        Write-Host "Запуск...`n" -ForegroundColor Green
        
        chcp 65001 > $null
        busted $file --filter="$hiddenTag"
    } else {
        Write-Host "Произошла ошибка извлечения маячка из словаря." -ForegroundColor Red
    }
} else {
    Write-Host "Запуск отменен." -ForegroundColor DarkGray
}