package.path = package.path .. ";" .. (debug.getinfo(1, "S").source:match("@?(.*[\\/])") or "") .. "?.lua"

local rex = require("rex_pcre")

_G.Re = {
    Replace = { FormatAll = 1 }, 
    
    create = function(pattern_str)
        local pcre_pattern = "(*UCP)(*UTF)" .. pattern_str

        local status, regex_obj = pcall(rex.new, pcre_pattern)
        if not status then
            error("Ошибка компиляции паттерна '" .. pattern_str .. "': " .. tostring(regex_obj))
        end
        return regex_obj 
    end,
    
    replace = function(text, mask, format, pattern_obj)
        local result, count = rex.gsub(text, pattern_obj, mask)
        return result
    end
}

local currentSelectionText = ""
local lastMessageBoxText = ""

_G.EditorAPI = {
    getSelection = function()
        return {
            extractText = function(self)
                return currentSelectionText
            end
        }
    end,
    messageBox = function(msg)
        lastMessageBoxText = msg
    end
}

_G.IS_TEST_ENV = true
require("anonymizer")

describe("Тестирование макроса обезличивания:", function()

    before_each(function()
        currentSelectionText = ""
        lastMessageBoxText = ""
    end)

    describe("Тесты ФИО #FIO_all", function()

        it("Должен маскировать полное ФИО #FIO_1", function()
            currentSelectionText = "Документ подписал Иванов Иван Иванович сегодня."
            _G.RunSanitizer()
            assert.are.equal("Документ подписал [ФИО] сегодня.", lastMessageBoxText)
        end)

        it("Должен маскировать ФИО с прямыми инициалами (с пробелом и без) #FIO_2", function()
            currentSelectionText = "Ответственный: Петров П.П. и Сидоров С. С."
            _G.RunSanitizer()
            assert.are.equal("Ответственный: [ФИО] и [ФИО]", lastMessageBoxText)
        end)

        it("Должен маскировать ФИО с обратными инициалами (с пробелом и без) #FIO_3", function()
            currentSelectionText = "выдал А.А. Андреев, принял Б. В. Борисов."
            _G.RunSanitizer()
            assert.are.equal("выдал [ФИО], принял [ФИО].", lastMessageBoxText)
        end)

        it("Должен маскировать двойные фамилии #FIO_4", function()
            currentSelectionText = "писатель Салтыков-Щедрин Михаил Евграфович"
            _G.RunSanitizer()
            assert.are.equal("писатель [ФИО]", lastMessageBoxText)
        end)

        it("НЕ должен склеивать ФИО через перенос строки #FIO_5", function()
            currentSelectionText = "Петров Пётр Петрович\nИванов Иван Иванович"
            _G.RunSanitizer()
            assert.are.equal("[ФИО]\n[ФИО]", lastMessageBoxText)
        end)
    end)

    describe("Тесты телефонных номеров #phone_all", function ()

        it("Должен маскировать стандартный номер через +7 #phone_1", function()
            currentSelectionText = "Мой номер +7(999)123-45-67 для связи."
            _G.RunSanitizer()
            assert.are.equal("Мой номер [ТЕЛЕФОН] для связи.", lastMessageBoxText)
        end)

        it("Должен маскировать номер через 8 с пробелами #phone_2", function()
            currentSelectionText = "Звоните: 8 903 111 22 33"
            _G.RunSanitizer()
            assert.are.equal("Звоните: [ТЕЛЕФОН]", lastMessageBoxText)
        end)

        it("Должен маскировать номер со сплошными цифрами #phone_3", function()
            currentSelectionText = "Телефон +79001234567 работает."
            _G.RunSanitizer()
            assert.are.equal("Телефон [ТЕЛЕФОН] работает.", lastMessageBoxText)
        end)
    end)

    describe("Тесты email-адресов #email_all", function ()

        it("Должен маскировать стандартный email #email_1", function()
            currentSelectionText = "Пишите на test@company.com"
            _G.RunSanitizer()
            assert.are.equal("Пишите на [EMAIL]", lastMessageBoxText)
        end)

        it("Должен маскировать email со сложным именем (точки, цифры, дефисы) #email_2", function()
            currentSelectionText = "Моя почта: ivan.ivanov-123_test@sub-domain.co.uk!"
            _G.RunSanitizer()
            assert.are.equal("Моя почта: [EMAIL]!", lastMessageBoxText)
        end)

        it("Должен корректно обрабатывать несколько email в одной строке #email_3", function()
            currentSelectionText = "Копии: a@a.ru, b@b.com"
            _G.RunSanitizer()
            assert.are.equal("Копии: [EMAIL], [EMAIL]", lastMessageBoxText)
        end)

        it("НЕ должен маскировать текст без символа @ #email_4", function()
            currentSelectionText = "Зайдите на www.test.com"
            _G.RunSanitizer()
            assert.are.equal("Зайдите на www.test.com", lastMessageBoxText)
        end)
    end)

    describe("Тесты ИНН #inn_all", function ()

        it("Должен маскировать ИНН физического лица (12 цифр) #inn_1", function()
            currentSelectionText = "Мой ИНН 123456789012 указан в договоре."
            _G.RunSanitizer()
            assert.are.equal("Мой ИНН [ИНН] указан в договоре.", lastMessageBoxText)
        end)

        it("Должен маскировать ИНН юридического лица (10 цифр) #inn_2", function()
            currentSelectionText = "ИНН организации: 1234567890."
            _G.RunSanitizer()
            assert.are.equal("ИНН организации: [ИНН].", lastMessageBoxText)
        end)

        it("НЕ должен маскировать слишком короткие номера (9 цифр) #inn_3", function()
            currentSelectionText = "Номер 123456789 не является ИНН."
            _G.RunSanitizer()
            assert.are.equal("Номер 123456789 не является ИНН.", lastMessageBoxText)
        end)
    end)

    describe("Тесты СНИЛС #snils_all", function()
        
        it("Должен маскировать СНИЛС в стандартном формате #snils_1", function()
            currentSelectionText = "СНИЛС 111-222-333 44 передан в отдел кадров."
            _G.RunSanitizer()
            assert.are.equal("СНИЛС [СНИЛС] передан в отдел кадров.", lastMessageBoxText)
        end)

        it("Не маскирует СНИЛС, написанный без дефисов #snils_2", function()
            currentSelectionText = "Вот мой СНИЛС 111222333 44"
            _G.RunSanitizer()
            assert.are.equal("Вот мой СНИЛС 111222333 44", lastMessageBoxText)
        end)
    end)

    describe("Тесты Паспорта #doc_all", function()
        
        it("Должен маскировать паспорт с обычным пробелом #doc_1", function()
            currentSelectionText = "Паспорт 4512 123456 выдан вчера."
            _G.RunSanitizer()
            assert.are.equal("Паспорт [ПАСПОРТ] выдан вчера.", lastMessageBoxText)
        end)

        it("Должен маскировать паспорт со знаком № #doc_2", function()
            currentSelectionText = "Серия 4512 № 123456"
            _G.RunSanitizer()
            assert.are.equal("Серия [ПАСПОРТ]", lastMessageBoxText)
        end)
    end)

    describe("Тесты адресов #addr_all", function ()

        it("Должен маскировать регион в обоих порядках слов #addr_1", function()
            currentSelectionText = "Московская обл. и республика Татарстан"
            _G.RunSanitizer()
            assert.are.equal("[РЕГИОН] и [РЕГИОН]", lastMessageBoxText)
        end)

        it("Должен маскировать почтовый индекс (6 цифр) #addr_2", function()
            currentSelectionText = "Письмо отправлено на индекс 123456."
            _G.RunSanitizer()
            assert.are.equal("Письмо отправлено на индекс [ИНДЕКС].", lastMessageBoxText)
        end)

        it("Должен маскировать стандартный город #addr_3", function()
            currentSelectionText = "Адрес: г. Москва, центр."
            _G.RunSanitizer()
            assert.are.equal("Адрес: [ГОРОД], центр.", lastMessageBoxText)
        end)

        it("Должен распознавать двойные названия городов #addr_4", function()
            currentSelectionText = "приехал в г. Йошкар-Ола вчера"
            _G.RunSanitizer()
            assert.are.equal("приехал в [ГОРОД] вчера", lastMessageBoxText)
        end)

        it("Игнорирует города без префикса 'г.' или 'с.' #addr_5", function()
            currentSelectionText = "Я поехал в Москву по делам."
            _G.RunSanitizer()
            assert.are.equal("Я поехал в Москву по делам.", lastMessageBoxText)
        end)

        it("Должен маскировать деревни и поселки #addr_6", function()
            currentSelectionText = "Происшествие в д. Косолапово и пос. Сосенское."
            _G.RunSanitizer()
            assert.are.equal("Происшествие в [НАСЕЛЕННЫЙ_ПУНКТ] и [НАСЕЛЕННЫЙ_ПУНКТ].", lastMessageBoxText)
        end)

        it("Должен распознавать двойные названия улиц #addr_7", function()
            currentSelectionText = "проживаю на улице Малой Бронной, д. 10"
            _G.RunSanitizer()
            assert.are.equal("проживаю на [УЛИЦА]", lastMessageBoxText)
        end)

        it("Не должен маскировать остаток предложения после улицы #addr_8", function()
            currentSelectionText = "На ул. Ленина уже неделю не работает светофор."
            _G.RunSanitizer()
            assert.are.equal("На [УЛИЦА] уже неделю не работает светофор.", lastMessageBoxText)
        end)

        it("Игнорирует улицы без префикса (ул., просп. и т.д.) #addr_9", function()
            currentSelectionText = "Живу на Тверской, 12."
            _G.RunSanitizer()
            assert.are.equal("Живу на Тверской, 12.", lastMessageBoxText)
        end)
    end)

    describe("Тесты дат #date_all", function ()
        it("Должен маскировать полную дату в формате ДД.ММ.ГГГГ #date_1", function()
            currentSelectionText = "Документ от 15.03.2024 подписан."
            _G.RunSanitizer()
            assert.are.equal("Документ от [ДАТА] подписан.", lastMessageBoxText)
        end)

        it("Должен маскировать короткую дату в формате ДД.ММ.ГГ #date_2", function()
            currentSelectionText = "Срок действия до 01.02.24 включительно."
            _G.RunSanitizer()
            assert.are.equal("Срок действия до [ДАТА] включительно.", lastMessageBoxText)
        end)

        it("Должен обрабатывать несколько дат, стоящих подряд #date_3", function()
            currentSelectionText = "Даты: 15.03.2024, 01.02.24 и 10.10.2022."
            _G.RunSanitizer()
            assert.are.equal("Даты: [ДАТА], [ДАТА] и [ДАТА].", lastMessageBoxText)
        end)

        it("Должен маскировать дату с месяцем прописью и 'г.' #date_4", function()
            currentSelectionText = "Заседание пройдет 25 декабря 2023 г."
            _G.RunSanitizer()
            assert.are.equal("Заседание пройдет [ДАТА]", lastMessageBoxText)
        end)

        it("Игнорирует текстовые даты без указания года #date_5", function()
            currentSelectionText = "Давайте встретимся 15 октября вечером."
            _G.RunSanitizer()
            assert.are.equal("Давайте встретимся 15 октября вечером.", lastMessageBoxText)
        end)
    end)

     describe("Тестирование паттерна [НОМЕР] num_all", function()
     
        it("Должен маскировать номер школы, оставляя само слово #num_1", function()
            currentSelectionText = "Ученик школы № 15 переведен."
            _G.RunSanitizer()
            assert.are.equal("Ученик школы [НОМЕР] переведен.", lastMessageBoxText)
        end)

        it("Должен маскировать сложные номера законов и договоров #num_2", function()
            currentSelectionText = "Согласно закону № 44-ФЗ и приказу №12/4-б."
            _G.RunSanitizer()
            assert.are.equal("Согласно закону [НОМЕР] и приказу [НОМЕР].", lastMessageBoxText)
        end)

        it("Должен автоматически ловить неизвестные документы #num_3", function()
            currentSelectionText = "Выпущено новое распоряжение № 999."
            _G.RunSanitizer()
            assert.are.equal("Выпущено новое распоряжение [НОМЕР].", lastMessageBoxText)
        end)

        it("Не пересекается с почтовым индексом если номер состоит из 6 цифр #num_4", function()
            currentSelectionText = "Договор №987654 подписан."
            _G.RunSanitizer()
            assert.are.equal("Договор [НОМЕР] подписан.", lastMessageBoxText)
        end)
    end)

    describe("Известные ограничения и баги макроса #err_all", function()
        
        it("ФИО захватывает любое первое слово с большой буквы #err_1", function()
            currentSelectionText = "Директор Иванов Иван Иванович"
            _G.RunSanitizer()
            assert.are.equal("[ФИО] Иванович", lastMessageBoxText)
        end)

        it("Случайные три слова с большой буквы #err_2", function()
            currentSelectionText = "Омский Государственный Университет"
            _G.RunSanitizer()
            assert.are.equal("[ФИО]", lastMessageBoxText)
        end)

        -- не маскирует городские телефоны, так как они пересекаются со СНИЛС
        it("Не маскирует короткие городские номера #err_3", function()
            currentSelectionText = "Городской телефон: 333-22-11"
            _G.RunSanitizer()
            assert.are.equal("Городской телефон: 333-22-11", lastMessageBoxText)
        end)
    end)
end)