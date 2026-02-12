# GPO Audit App

Веб-приложение для аудита GPO-экспортов из GPMC (HTML/XML) с хранением результатов в PostgreSQL.

## Что умеет

- Загрузка отчёта GPMC через UI.
- Проверка по baseline-правилам (`best_practices.json` или ваш JSON).
- Единый экран с:
  - сводкой по риску,
  - таблицей «что исправить в первую очередь»,
  - фильтрами прямо в заголовках таблицы.
- Детальный просмотр запуска с фильтрами и пагинацией.
- Экспорт отчётов в PDF (print view).

## Требования

- Python `3.11+` (проверено на `3.13`)
- PostgreSQL `13+`

## Быстрый старт

1. Перейдите в папку проекта:

```bash
cd /Users/kp/useful_scripts/gpo_audit_app
```

2. Создайте и активируйте виртуальное окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Установите зависимости:

```bash
pip install -r requirements.txt
```

4. Создайте БД (пример):

```bash
createdb gpo_audit
```

5. Укажите строку подключения:

```bash
export DATABASE_URL="postgresql+psycopg://<user>:<password>@localhost:5432/gpo_audit"
```

Если укажете `postgresql://...`, приложение автоматически переключит драйвер на `postgresql+psycopg://...`.

6. Запустите приложение:

```bash
.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Откройте: [http://127.0.0.1:8000](http://127.0.0.1:8000)

## Как пользоваться

1. Откройте вкладку **Загрузка**.
2. Загрузите `AllGPOs.html` (или XML) из GPMC.
3. Опционально загрузите свой JSON с правилами.
4. Запустите аудит.
5. Откройте результат:
   - на главной: приоритизированный список исправлений,
   - в запуске: полный детальный разбор.

## Структура

- `app/main.py` — FastAPI роуты и обработка UI.
- `app/models.py` — SQLAlchemy модели.
- `app/db.py` — подключение к PostgreSQL.
- `app/services.py` — фильтрация/пагинация результатов.
- `app/templates/` — Jinja2 шаблоны.
- `app/static/style.css` — общий стиль интерфейса.
- `gpo_audit.py` — движок парсинга и аудита.
- `best_practices.json` — baseline-правила по умолчанию.

## Troubleshooting

- `ModuleNotFoundError: No module named 'psycopg2'`
  - Используйте `postgresql+psycopg://...` в `DATABASE_URL`.
- `connection refused`
  - Проверьте, что PostgreSQL запущен и БД создана.
- Не видно изменений в UI
  - Сделайте hard refresh в браузере (`Cmd+Shift+R` / `Ctrl+F5`).
