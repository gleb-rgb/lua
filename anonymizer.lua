---@diagnostic disable: undefined-global
local CORE = {}

local patterns = {
	-- ФИО
	russianName = Re.create("\\b[А-Я][а-яёЁ]+(?:-[А-Я][а-яёЁ]+)*[ \\t]+[А-Я][а-яёЁ]+(?:-[А-Я][а-яёЁ]+)*[ \\t]+[А-Я][а-яёЁ]+(?:-[А-Я][а-яёЁ]+)*\\b"),
	shortName = Re.create("[А-Я]\\.[ \\t]*[А-Я]\\.[ \\t]*[А-Я][а-яёЁ]+(?:-[А-Я][а-яёЁ]+)*"),
	reverseInitials = Re.create("[А-Я][а-яёЁ]+(?:-[А-Я][а-яёЁ]+)*[ \\t]+[А-Я]\\.[ \\t]*[А-Я]\\."),
	
	-- Контакты
	phone = Re.create("(?:\\+7|8)[ \\t\\-\\(\\)]*\\d{3}[ \\t\\-\\(\\)]*\\d{3}[ \\t\\-\\(\\)]*\\d{2}[ \\t\\-\\(\\)]*\\d{2}"),
	email = Re.create("[\\w.!#$%&'*+/=?^_`{|}~-]+@[\\w-]+(?:\\.[\\w-]+)+"),
    
    --Документы
	inn = Re.create("\\b\\d{10,12}\\b"),
    snils = Re.create("\\b\\d{3}-\\d{3}-\\d{3}[ \\t]*\\d{2}\\b"),
    passport = Re.create("\\b\\d{4}[ \\t]*№?[ \\t]*\\d{6}\\b"),
	
	-- Адреса
	city = Re.create("\\b[гс]\\.[ \\t]*[А-Я][а-яёЁ]+(?:-[а-яёЁ]+)?(?:[- \\t]+[А-Я][а-яёЁ]+)*"),
	street = Re.create("(?:ул(?:ица|ице)?|просп(?:ект)?|пр(?:оезд)?|пер(?:еулок)?|бульвар|б-р|наб(?:ережная)?|ш(?:оссе)?)\\.?[ \\t]*[А-Я][а-яёЁ]*(?:(?:[ \\t]+[А-Я]|-[А-Я])[а-яёЁ]*)*(?:(?:[, \\t]+|[ \\t]*№[ \\t]*)\\d+[А-Яа-я]?)?(?:[, \\t]+(?:д\\.|дом|корп\\.|корпус|кв\\.|квартира)[ \\t]*\\d+)*"),
	postalCode = Re.create("\\b\\d{6}\\b"),
	region = Re.create("(?:[А-Я][а-яёЁ-]+[ \\t]+(?:обл\\.|область|край|респ\\.|республика)|(?:обл\\.|область|край|респ\\.|республика)[ \\t]+[А-Я][а-яёЁ-]+)"),
	village = Re.create("(?:д\\.|деревня|п\\.|поселок|пос\\.)[ \\t]+[А-Я][а-яёЁ-]+(?:[ \\t]+[А-Я][а-яёЁ-]+)*"),
	
	-- Даты
	dd_mm_yyyy = Re.create("\\b(?:0[1-9]|[12][0-9]|3[01])\\.(?:0[1-9]|1[0-2])\\.(?:19|20)\\d{2}\\b"),
	dd_mm_yy = Re.create("\\b(?:0[1-9]|[12][0-9]|3[01])\\.(?:0[1-9]|1[0-2])\\.\\d{2}\\b"),
	textDate = Re.create("\\b(?:0?[1-9]|[12][0-9]|3[01])\\s+(?:январ[ья]|феврал[ья]|март[а]?|апрел[ья]|ма[йя]|июн[ья]|июл[ья]|август[а]?|сентябр[ья]|октябр[ья]|ноябр[ья]|декабр[ья])\\s+(?:19|20)?\\d{2}\\s*г\\.?"),
	
	-- №
	genericNumber = Re.create("№[ \\t]*\\d+(?:[-/][А-Яа-яЁёA-Za-z0-9]+)*"),
	
}

local logData = {
    timestamp = os.date("%Y-%m-%d %H:%M:%S"),
    operations = {}
}

function CORE.log(message)
    table.insert(logData.operations, {
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        message = message
    })
    
    print("LOG: " .. message)
end

function CORE.sanitize(text)
	CORE.log("Начало обработки текста")
	
    if not text or text == "" then 
    	CORE.log("Пустой текст для обработки")
        return text, 0, {}
    end
        
    local result = text            
    local totalChanges = 0          
    local statistics = {}  
    
    local patternMasks = {
        {pattern = patterns.region, mask = "[РЕГИОН]", type = "region"},
    	{pattern = patterns.village, mask = "[НАСЕЛЕННЫЙ_ПУНКТ]", type = "village"},
    	{pattern = patterns.city, mask = "[ГОРОД]", type = "city"},
    	{pattern = patterns.street, mask = "[УЛИЦА]", type = "street"},
    
        {pattern = patterns.russianName, mask = "[ФИО]", type = "name"},
        {pattern = patterns.shortName, mask = "[ФИО]", type = "name"}, 
        {pattern = patterns.reverseInitials, mask = "[ФИО]", type = "name"},
        
        {pattern = patterns.phone, mask = "[ТЕЛЕФОН]", type = "phone"},
        {pattern = patterns.email, mask = "[EMAIL]", type = "email"},
        
        {pattern = patterns.inn, mask = "[ИНН]", type = "inn"},
        {pattern = patterns.snils, mask = "[СНИЛС]", type = "snils"},
        {pattern = patterns.passport, mask = "[ПАСПОРТ]", type = "passport"},
        
        {pattern = patterns.genericNumber, mask = "[НОМЕР]", type = "genericNumber"},
        
    	{pattern = patterns.postalCode, mask = "[ИНДЕКС]", type = "postal_code"},
        
		{pattern = patterns.dd_mm_yyyy, mask = "[ДАТА]", type = "date"},
    	{pattern = patterns.dd_mm_yy, mask = "[ДАТА]", type = "date"},
    	{pattern = patterns.textDate, mask = "[ДАТА]", type = "date"},
 
    }   

	for _, config in ipairs(patternMasks) do
        if config.pattern then 
            local before = result
            
            result = Re.replace(
                result,          
                config.mask,      
                Re.Replace.FormatAll, 
                config.pattern   
            )
            
            if result ~= before then
                local count = CORE.countMask(result) - CORE.countMask(before)
                CORE.log("Найдено: " .. config.type .. " (" .. count .. " шт.)")
                statistics[config.type] = (statistics[config.type] or 0) + count
                totalChanges = totalChanges + count
            end
        else
        	CORE.log("ОШИБКА: Паттерн не создан для типа: " .. config.type)
        end
    end
    
    if totalChanges > 0 then
        CORE.log("Обработка завершена. Найдено данных: " .. totalChanges .. " элементов")
        
        local statsText = "Статистика: "
        for typeName, count in pairs(statistics) do
            statsText = statsText .. typeName .. "=" .. count .. ", "
        end
        CORE.log(statsText)
    else
        CORE.log("Обработка завершена. Персональные данные не найдены")
    end
    
    return result, totalChanges, statistics
end

function CORE.countMask(text)
    local count = 0
    for _ in string.gmatch(text, "%[[^%]]+%]") do
    	count = count + 1
    end
    return count
end

function CORE.getLogs()
    return logData
end

function CORE.writeLogsToDocument()
    if #logData.operations == 0 then
        CORE.log("Нет операций для записи в лог-таблицу.")
        return
    end
    
    local range = document:getRange()
    local pos = range:getEnd()
    
    local rowsCount = 1 + #logData.operations
    
    local table = pos:insertTable(rowsCount, 2, "LogTable")
    
    table:getCell("A1"):setText("Время")
    table:getCell("B1"):setText("Сообщение")
    
    for i, entry in ipairs(logData.operations) do
        local rowNum = i + 1
        local timeCellAddr = "A" .. rowNum
        local msgCellAddr = "B" .. rowNum
        table:getCell(timeCellAddr):setText(entry.timestamp)
        table:getCell(msgCellAddr):setText(entry.message)
    end
    
     -- пишет что не поддерживает скрытие для данного типа документа
     --table:setRowsVisible(0, rowsCount, false)
     --CORE.log("Все строки лог-таблицы скрыты с помощью setRowsVisible.")
end

function RunSanitizer()
    CORE.log("Запуск макроса")
    
    local selection = EditorAPI.getSelection()
    
    if not selection then
        CORE.log("Текст не выделен")
        EditorAPI.messageBox("Текст не выделен.\nВыделите текст или весь документ (Ctrl+A).")
        return nil
    end
    
    local textToProcess = selection:extractText()
    
    if string.len(textToProcess) == 0 then
        CORE.log("Текст пуст")
        EditorAPI.messageBox("Текст не выделен.\nВыделите текст или весь документ (Ctrl+A).")
        return nil
    end
    
    CORE.log("Текст получен, длина: " .. string.len(textToProcess) .. " символов")
    
    local sanitizedText, changesCount, statistics = CORE.sanitize(textToProcess)
    
    EditorAPI.messageBox(sanitizedText)
    
    CORE.log("Завершено успешно")
    
    --CORE.writeLogsToDocument() ПОКА НЕ РЕШИЛИ ЧТО С ЛОГАМИ
    
    return {
        processedLength = string.len(textToProcess),
        changesCount = changesCount,
    }
end

if not _G.IS_TEST_ENV then
    RunSanitizer()
end

return patterns