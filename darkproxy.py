#!/usr/bin/env python3
"""
IPv6 Proxy Server Manager - Исправленная версия
Автор: Основано на bash скрипте от darkkkxold, переписано на Python
Версия: 2.1.0 (Python) - ИСПРАВЛЕННАЯ ВЕРСИЯ
Дата: 2025

ИСПРАВЛЕНИЯ В ЭТОЙ ВЕРСИИ:
1. При ротации сохраняются логины/пароли и количество портов
2. Исправлена конфигурация HTTP прокси (теперь 'proxy' вместо 'socks')
3. Улучшена стабильность работы с состоянием прокси

Современный IPv6 прокси-сервер с автоматической ротацией подсетей:
- Берет /48 подсеть и каждый день создает новую /64 подсеть
- Генерирует случайные IPv6 адреса для прокси
- Ежедневная ротация подсетей и IP адресов с сохранением аутентификации
- Асинхронное управление процессами
- Структурированное логирование
- Типизированный код с dataclasses
"""

import asyncio
import ipaddress
import logging
import os
import random
import resource
import secrets
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import json
import signal
import shutil
import tempfile
from urllib.parse import urlencode
import aiohttp
import aiofiles
import pickle

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ipv6-proxy-manager.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('IPv6ProxyManager')


class ProxyType(Enum):
    """Типы прокси серверов"""
    HTTP = "http"
    SOCKS5 = "socks5"


class AuthMode(Enum):
    """Режимы аутентификации"""
    NONE = "none"
    SINGLE = "single"
    RANDOM = "random"


@dataclass
class ProxyConfig:
    """Конфигурация прокси-сервера"""
    parent_subnet: str
    proxy_count: int = 100
    proxy_type: ProxyType = ProxyType.SOCKS5
    auth_mode: AuthMode = AuthMode.RANDOM
    username: Optional[str] = None
    password: Optional[str] = None
    start_port: int = 30000
    rotating_interval: int = 0  # 0 = только ежедневно
    interface: str = "eth0"
    localhost_only: bool = False
    child_subnet_size: int = 64
    allowed_hosts: Optional[str] = None
    denied_hosts: Optional[str] = None

    def __post_init__(self):
        """Валидация конфигурации"""
        if self.auth_mode == AuthMode.SINGLE and (not self.username or not self.password):
            raise ValueError("Username и password обязательны для режима SINGLE")

        if self.proxy_count <= 0 or self.proxy_count > 50000:
            raise ValueError("Количество прокси должно быть от 1 до 50000")

        if self.start_port < 1024 or self.start_port + self.proxy_count > 65536:
            raise ValueError("Неверный диапазон портов")

        # Валидация IPv6 подсети
        try:
            network = ipaddress.IPv6Network(f"{self.parent_subnet}::/48", strict=False)
            logger.info(f"Валидная родительская подсеть: {network}")
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Неверная IPv6 подсеть: {e}")


@dataclass
class ProxyInstance:
    """Экземпляр прокси"""
    port: int
    ipv6_address: ipaddress.IPv6Address
    username: Optional[str] = None
    password: Optional[str] = None

    def get_proxy_string(self, backconnect_ip: str) -> str:
        """Возвращает строку подключения к прокси"""
        if self.username and self.password:
            return f"{backconnect_ip}:{self.port}:{self.username}:{self.password}"
        return f"{backconnect_ip}:{self.port}"


@dataclass
class ProxyState:
    """Состояние прокси для сохранения между ротациями"""
    instances: List[ProxyInstance]
    config: ProxyConfig
    creation_date: datetime

    def save_to_file(self, file_path: Path):
        """Сохраняет состояние в файл"""
        with open(file_path, 'wb') as f:
            pickle.dump(self, f)

    @classmethod
    def load_from_file(cls, file_path: Path) -> Optional['ProxyState']:
        """Загружает состояние из файла"""
        if not file_path.exists():
            return None
        try:
            with open(file_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"Не удалось загрузить состояние: {e}")
            return None


class SystemOptimizer:
    """Оптимизация системы для IPv6 прокси"""

    @staticmethod
    async def optimize_system():
        """Оптимизирует систему для работы с IPv6 прокси"""
        logger.info("Применяем системные оптимизации...")

        sysctl_settings = {
            "net.ipv4.route.min_adv_mss": "1460",
            "net.ipv4.tcp_timestamps": "0",
            "net.ipv4.tcp_window_scaling": "0",
            "net.ipv4.icmp_echo_ignore_all": "1",
            "net.ipv4.tcp_max_syn_backlog": "4096",
            "net.ipv4.conf.all.forwarding": "1",
            "net.ipv4.ip_nonlocal_bind": "1",
            "net.ipv6.conf.all.proxy_ndp": "1",
            "net.ipv6.conf.default.forwarding": "1",
            "net.ipv6.conf.all.forwarding": "1",
            "net.ipv6.ip_nonlocal_bind": "1",
            "net.ipv4.ip_default_ttl": "128",
            "net.ipv4.tcp_syn_retries": "2",
            "net.ipv4.tcp_fin_timeout": "30",
            "net.ipv4.tcp_keepalive_time": "7200",
            "net.ipv4.tcp_rmem": "4096 87380 6291456",
            "net.ipv4.tcp_wmem": "4096 16384 6291456"
        }

        # Применяем sysctl настройки
        for key, value in sysctl_settings.items():
            try:
                await asyncio.create_subprocess_exec(
                    'sysctl', '-w', f"{key}={value}",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
            except Exception as e:
                logger.warning(f"Не удалось применить {key}: {e}")

        # Устанавливаем лимиты файлов
        limits_conf = "/etc/security/limits.conf"
        limits_content = [
            "* hard nofile 999999\n",
            "* soft nofile 999999\n"
        ]

        try:
            async with aiofiles.open(limits_conf, 'a') as f:
                for limit in limits_content:
                    await f.write(limit)
        except Exception as e:
            logger.warning(f"Не удалось обновить limits.conf: {e}")

        # Отключаем firewalld если есть
        try:
            await asyncio.create_subprocess_exec(
                'systemctl', 'stop', 'firewalld',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.create_subprocess_exec(
                'systemctl', 'disable', 'firewalld',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
        except:
            pass  # Не критично если firewalld нет

        logger.info("Системные оптимизации применены")


class IPv6Manager:
    """Управление IPv6 адресами и подсетями"""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.current_subnet: Optional[ipaddress.IPv6Network] = None

    def generate_daily_subnet(self) -> ipaddress.IPv6Network:
        """Генерирует ежедневную подсеть на основе даты"""
        day_of_year = datetime.now().timetuple().tm_yday
        hex_block = f"{day_of_year:04x}"

        subnet_str = f"{self.config.parent_subnet}:{hex_block}::/{self.config.child_subnet_size}"
        return ipaddress.IPv6Network(subnet_str, strict=False)

    def generate_random_ipv6(self, subnet: ipaddress.IPv6Network) -> ipaddress.IPv6Address:
        """Генерирует случайный IPv6 адрес в подсети"""
        network_int = int(subnet.network_address)
        host_bits = 128 - subnet.prefixlen
        max_hosts = (1 << host_bits) - 1

        random_host = random.randint(1, max_hosts)
        return ipaddress.IPv6Address(network_int + random_host)

    async def add_ipv6_to_interface(self, address: ipaddress.IPv6Address):
        """Добавляет IPv6 адрес к интерфейсу"""
        try:
            process = await asyncio.create_subprocess_exec(
                'ip', '-6', 'addr', 'add', str(address), 'dev', self.config.interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
        except Exception as e:
            logger.error(f"Ошибка добавления IPv6 {address}: {e}")

    async def remove_ipv6_from_interface(self, address: ipaddress.IPv6Address):
        """Удаляет IPv6 адрес из интерфейса"""
        try:
            process = await asyncio.create_subprocess_exec(
                'ip', '-6', 'addr', 'del', str(address), 'dev', self.config.interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
        except Exception as e:
            logger.warning(f"Ошибка удаления IPv6 {address}: {e}")


class ThreeProxyManager:
    """Управление 3proxy сервером"""

    def __init__(self, config: ProxyConfig, work_dir: Path):
        self.config = config
        self.work_dir = work_dir
        self.proxy_process: Optional[asyncio.subprocess.Process] = None
        self.config_file = work_dir / "3proxy" / "3proxy.cfg"

    async def install_3proxy(self):
        """Устанавливает 3proxy"""
        logger.info("Устанавливаем 3proxy...")

        proxy_dir = self.work_dir / "3proxy"
        proxy_dir.mkdir(parents=True, exist_ok=True)

        # Скачиваем и собираем 3proxy
        temp_dir = Path(tempfile.mkdtemp())
        try:
            # Скачиваем
            process = await asyncio.create_subprocess_exec(
                'wget', 'https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz',
                '-O', str(temp_dir / '3proxy.tar.gz'),
                cwd=temp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()

            # Распаковываем
            process = await asyncio.create_subprocess_exec(
                'tar', '-xf', '3proxy.tar.gz',
                cwd=temp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()

            # Собираем
            build_dir = temp_dir / "3proxy-0.9.4"
            process = await asyncio.create_subprocess_exec(
                'make', '-f', 'Makefile.Linux',
                cwd=build_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()

            # Копируем исполняемый файл
            shutil.copy2(build_dir / "bin" / "3proxy", proxy_dir / "3proxy")
            os.chmod(proxy_dir / "3proxy", 0o755)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        logger.info("3proxy установлен успешно")

    async def start_proxy_server(self, proxy_instances, backconnect_ip: str):
        """Запускает сервер 3proxy с правильным управлением лимитами"""
        logger.info("Запускаем 3proxy сервер...")

        # Останавливаем если уже запущен
        await self.stop_proxy_server()

        # Генерируем конфигурацию
        config_content = self.generate_config(proxy_instances, backconnect_ip)

        # Сохраняем конфигурацию
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(self.config_file, 'w') as f:
            await f.write(config_content)

        # Правильно устанавливаем лимиты ресурсов
        try:
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            needed_limit = len(proxy_instances) * 2 + 1000
            target_limit = min(needed_limit, hard_limit)

            if soft_limit < target_limit:
                logger.info(f"Увеличиваем лимит открытых файлов с {soft_limit} до {target_limit}")
                resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard_limit))
            else:
                logger.info(f"Лимит открытых файлов уже достаточен: {soft_limit}")

        except (ValueError, OSError) as e:
            logger.warning(f"Не удалось установить лимит RLIMIT_NOFILE: {e}")

        # Функция для установки лимитов в дочернем процессе
        def preexec_fn():
            """Настройка ресурсов в дочернем процессе перед exec"""
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                needed = len(proxy_instances) * 2 + 1000
                target = min(needed, hard)
                if soft < target:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))

                try:
                    soft_proc, hard_proc = resource.getrlimit(resource.RLIMIT_NPROC)
                    resource.setrlimit(resource.RLIMIT_NPROC, (min(1024, hard_proc), hard_proc))
                except:
                    pass

            except Exception:
                pass

        # Запускаем 3proxy
        try:
            logger.info("Запускаем 3proxy с preexec_fn для установки лимитов")
            self.proxy_process = await asyncio.create_subprocess_exec(
                str(self.work_dir / "3proxy" / "3proxy"),
                str(self.config_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=preexec_fn
            )
        except Exception as e:
            logger.error(f"Ошибка запуска 3proxy: {e}")
            raise

        # Ждем немного для инициализации
        await asyncio.sleep(2)

        logger.info(f"3proxy запущен с PID {self.proxy_process.pid}")
        logger.info(
            f"Доступно {len(proxy_instances)} прокси на портах {self.config.start_port}-{self.config.start_port + len(proxy_instances) - 1}")

    async def stop_proxy_server(self):
        """Останавливает сервер 3proxy"""
        if self.proxy_process:
            try:
                self.proxy_process.terminate()
                await asyncio.wait_for(self.proxy_process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self.proxy_process.kill()
                await self.proxy_process.wait()
            except:
                pass
            self.proxy_process = None

        # Убиваем все процессы 3proxy
        try:
            process = await asyncio.create_subprocess_exec(
                'pkill', '-f', '3proxy',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
        except:
            pass

        logger.info("3proxy остановлен")

    def is_running(self) -> bool:
        """Проверяет, запущен ли 3proxy"""
        return self.proxy_process is not None and self.proxy_process.returncode is None

    def generate_config(self, proxy_instances, backconnect_ip: str) -> str:
        """
        Генерирует корректную конфигурацию 3proxy для IPv6 с учетом best practices 2025
        """
        config_lines = [
            "daemon",
            "nserver 1.1.1.1",
            "nserver 8.8.8.8",
            "nscache 65536",
            f"maxconn {len(proxy_instances) * 10}",
        ]

        # Настройки сети для IPv6
        config_lines.extend([
            "# Сетевые настройки для IPv6",
            f"internal {backconnect_ip}",
            "external ::",  # Автоматический выбор внешнего IPv6 адреса
            ""
        ])

        # Аутентификация
        config_lines.extend(self._generate_auth_config())

        # Глобальные ACL правила
        config_lines.extend(self._generate_global_acl())

        # Генерация прокси экземпляров
        for i, instance in enumerate(proxy_instances):
            config_lines.extend(self._generate_proxy_instance(instance, i))

        return "\n".join(config_lines)

    def _generate_auth_config(self) -> list[str]:
        """Генерирует секцию аутентификации"""
        auth_lines = ["# Настройки аутентификации"]

        if self.config.auth_mode.value == "none":
            auth_lines.extend([
                "auth iponly",
                "# Без аутентификации - доступ по IP",
                ""
            ])
        elif self.config.auth_mode.value == "single":
            auth_lines.extend([
                "auth strong",
                "# Единая аутентификация для всех прокси",
                f"users {self.config.username}:CL:{self.config.password}",
                ""
            ])
        else:  # random mode
            auth_lines.extend([
                "auth strong",
                "# Индивидуальная аутентификация для каждого прокси",
                "# Пользователи определяются для каждого экземпляра отдельно",
                ""
            ])

        return auth_lines

    def _generate_global_acl(self) -> list[str]:
        """Генерирует глобальные ACL правила"""
        acl_lines = ["# Глобальные правила доступа"]

        # Блокируем локальные адреса для безопасности
        acl_lines.extend([
            "deny * * 127.0.0.0/8",
            "deny * * 10.0.0.0/8",
            "deny * * 172.16.0.0/12",
            "deny * * 192.168.0.0/16",
            "deny * * ::1",
            "deny * * fc00::/7",
            ""
        ])

        # Настраиваем разрешенные/запрещенные хосты
        if self.config.denied_hosts:
            acl_lines.extend([
                f"# Запрещенные хосты: {self.config.denied_hosts}",
                f"deny * * {self.config.denied_hosts}",
                ""
            ])

        if self.config.allowed_hosts:
            acl_lines.extend([
                f"# Разрешенные хосты: {self.config.allowed_hosts}",
                f"allow * * {self.config.allowed_hosts}",
                "deny *",  # Запрещаем все остальное
                ""
            ])

        return acl_lines

    def _generate_proxy_instance(self, instance, index: int) -> list[str]:
        """Генерирует конфигурацию для одного прокси экземпляра"""
        instance_lines = [
            f"# Прокси экземпляр #{index + 1}: {instance.ipv6_address}:{instance.port}",
        ]

        # Для режима случайной аутентификации создаем отдельный ACL блок
        if self.config.auth_mode.value == "random" and instance.username:
            instance_lines.extend([
                "flush",  # Сбрасываем предыдущие ACL
                f"users {instance.username}:CL:{instance.password}",
                f"allow {instance.username}",
                ""
            ])
        elif self.config.auth_mode.value == "single":
            instance_lines.extend([
                f"allow {self.config.username}",
            ])
        else:  # none mode
            instance_lines.extend([
                "allow *",
            ])

        # Генерируем строку прокси сервиса
        proxy_line = self._get_proxy_line(instance)
        instance_lines.extend([
            proxy_line,
            ""
        ])

        return instance_lines

    def _get_proxy_line(self, instance) -> str:
        """
        Генерирует правильную строку конфигурации прокси
        ИСПРАВЛЕНО: убраны конфликтующие параметры, добавлена поддержка IPv6
        """
        base_params = f"-p{instance.port}"

        # IPv6 биндинг и внешний адрес
        ipv6_params = f"-e{instance.ipv6_address}"

        if self.config.proxy_type.value == "http":
            # HTTP/HTTPS прокси
            # -n отключает NTLM (нужно для Unix паролей)
            # НЕ используем -a (анонимный режим) если есть аутентификация
            if self.config.auth_mode.value == "none":
                return f"proxy -n -a {base_params} {ipv6_params}"
            else:
                return f"proxy -n {base_params} {ipv6_params}"
        else:  # SOCKS5
            # SOCKS прокси
            # -a означает "разрешить анонимное соединение" только для SOCKS
            if self.config.auth_mode.value == "none":
                return f"socks -a {base_params} {ipv6_params}"
            else:
                # Для SOCKS с аутентификацией не используем -a
                return f"socks {base_params} {ipv6_params}"


class FileUploader:
    """Загрузка файлов на file.io"""

    @staticmethod
    async def upload_to_fileio(file_path: Path) -> Optional[str]:
        """Загружает файл на file.io и возвращает ссылку"""
        try:
            async with aiohttp.ClientSession() as session:
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field('file', f, filename=file_path.name)

                    async with session.post('https://file.io', data=data) as response:
                        if response.status == 200:
                            result = await response.json()
                            return result.get('link')
        except Exception as e:
            logger.error(f"Ошибка загрузки файла: {e}")
        return None


class CronManager:
    """Управление cron задачами"""

    def __init__(self, script_path: Path):
        self.script_path = script_path

    async def setup_cron_jobs(self, config: ProxyConfig):
        """Настраивает cron задачи"""
        logger.info("Настраиваем cron задачи...")

        cron_lines = []

        # Автозапуск при перезагрузке
        cmd = f"@reboot {sys.executable} {self.script_path} --parent-subnet '{config.parent_subnet}' --start"
        cron_lines.append(cmd)

        # Ежедневная ротация в 00:01
        cmd = f"1 0 * * * {sys.executable} {self.script_path} --proxy-type '{config.proxy_type.value}' --proxy-count {config.proxy_count} --parent-subnet '{config.parent_subnet}' --rotate"
        cron_lines.append(cmd)

        # Дополнительная ротация если настроена
        if config.rotating_interval > 0:
            cmd = f"*/{config.rotating_interval} * * * * {sys.executable} {self.script_path} --proxy-type '{config.proxy_type.value}' --proxy-count {config.proxy_count} --parent-subnet '{config.parent_subnet}' --rotate"
            cron_lines.append(cmd)

        # Сохраняем в временный файл
        temp_cron = Path("/tmp/ipv6_proxy_cron")
        async with aiofiles.open(temp_cron, 'w') as f:
            await f.write("\n".join(cron_lines) + "\n")

        # Применяем
        process = await asyncio.create_subprocess_exec(
            'crontab', str(temp_cron),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.wait()

        temp_cron.unlink(missing_ok=True)
        logger.info("Cron задачи настроены")

    async def remove_cron_jobs(self):
        """Удаляет cron задачи"""
        try:
            process = await asyncio.create_subprocess_exec(
                'crontab', '-r',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
            logger.info("Cron задачи удалены")
        except Exception as e:
            logger.warning(f"Не удалось удалить cron задачи: {e}")


class IPv6ProxyManager:
    """Основной класс управления IPv6 прокси-сервером"""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.work_dir = Path.home() / "ipv6-proxy-server"
        self.state_file = self.work_dir / "proxy_state.pkl"
        self.ipv6_manager = IPv6Manager(config)
        self.proxy_manager = ThreeProxyManager(config, self.work_dir)
        self.cron_manager = CronManager(Path(__file__))
        self.current_instances: List[ProxyInstance] = []
        self.current_ipv6_addresses: List[ipaddress.IPv6Address] = []

    async def setup_system(self):
        """Настройка системы"""
        logger.info("Настраиваем систему...")

        # Создаем рабочую директорию
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Проверяем IPv6
        await self._check_ipv6_support()

        # Оптимизируем систему
        await SystemOptimizer.optimize_system()

        # Устанавливаем зависимости
        await self._install_dependencies()

        # Устанавливаем 3proxy
        await self.proxy_manager.install_3proxy()

        logger.info("Система настроена")

    async def _check_ipv6_support(self):
        """Проверяет поддержку IPv6"""
        try:
            process = await asyncio.create_subprocess_exec(
                'ping6', '-c', '1', 'google.com',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            result = await process.wait()
            if result != 0:
                raise Exception("IPv6 подключение недоступно")
        except Exception as e:
            logger.error(f"Ошибка проверки IPv6: {e}")
            raise

    async def _install_dependencies(self):
        """Устанавливает зависимости"""
        packages = ["make", "g++", "wget", "curl", "cron", "zip", "openssl", "jq"]

        # Обновляем пакеты
        process = await asyncio.create_subprocess_exec(
            'apt', 'update',
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await process.wait()

        # Устанавливаем пакеты
        for package in packages:
            process = await asyncio.create_subprocess_exec(
                'apt', 'install', '-y', package,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()

    async def generate_proxy_instances(self, preserve_auth: bool = False) -> List[ProxyInstance]:
        """
        ИСПРАВЛЕНИЕ: Генерирует экземпляры прокси с возможностью сохранения аутентификации
        При preserve_auth=True сохраняет логины/пароли из существующего состояния
        """
        logger.info(f"Генерируем {self.config.proxy_count} прокси экземпляров...")

        # Загружаем существующее состояние если нужно сохранить аутентификацию
        saved_auth = {}
        if preserve_auth:
            saved_state = ProxyState.load_from_file(self.state_file)
            if saved_state and len(saved_state.instances) == self.config.proxy_count:
                for i, instance in enumerate(saved_state.instances):
                    saved_auth[i] = (instance.username, instance.password)
                logger.info("Сохраняем существующие логины/пароли при ротации")

        # Генерируем ежедневную подсеть
        subnet = self.ipv6_manager.generate_daily_subnet()
        logger.info(f"Используем подсеть: {subnet}")

        instances = []
        for i in range(self.config.proxy_count):
            port = self.config.start_port + i
            ipv6_addr = self.ipv6_manager.generate_random_ipv6(subnet)

            # ИСПРАВЛЕНИЕ: используем сохраненную аутентификацию или генерируем новую
            username = password = None
            if i in saved_auth:
                # Используем сохраненные логин/пароль
                username, password = saved_auth[i]
                logger.debug(f"Используем сохраненную аутентификацию для прокси {i + 1}")
            else:
                # Генерируем новую аутентификацию
                if self.config.auth_mode == AuthMode.SINGLE:
                    username, password = self.config.username, self.config.password
                elif self.config.auth_mode == AuthMode.RANDOM:
                    username = secrets.token_urlsafe(8)
                    password = secrets.token_urlsafe(12)

            instance = ProxyInstance(
                port=port,
                ipv6_address=ipv6_addr,
                username=username,
                password=password
            )
            instances.append(instance)

        logger.info(f"Сгенерировано {len(instances)} прокси экземпляров")
        return instances

    def save_proxy_state(self, instances: List[ProxyInstance]):
        """ИСПРАВЛЕНИЕ: Сохраняет состояние прокси для последующих ротаций"""
        state = ProxyState(
            instances=instances,
            config=self.config,
            creation_date=datetime.now()
        )
        state.save_to_file(self.state_file)
        logger.info(f"Состояние прокси сохранено в {self.state_file}")

    async def add_ipv6_addresses(self, instances: List[ProxyInstance]):
        """Добавляет IPv6 адреса к интерфейсу"""
        logger.info("Добавляем IPv6 адреса к интерфейсу...")

        tasks = []
        for instance in instances:
            task = self.ipv6_manager.add_ipv6_to_interface(instance.ipv6_address)
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)
        self.current_ipv6_addresses = [inst.ipv6_address for inst in instances]

    async def remove_ipv6_addresses(self):
        """Удаляет IPv6 адреса из интерфейса"""
        if not self.current_ipv6_addresses:
            return

        logger.info("Удаляем IPv6 адреса из интерфейса...")

        tasks = []
        for address in self.current_ipv6_addresses:
            task = self.ipv6_manager.remove_ipv6_from_interface(address)
            tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)
        self.current_ipv6_addresses.clear()

    def get_backconnect_ip(self) -> str:
        """Определяет IP для обратного подключения"""
        if self.config.localhost_only:
            return "127.0.0.1"

        # Получаем IP интерфейса
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.config.interface],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and not '127.0.0.1' in line:
                    ip = line.split()[1].split('/')[0]
                    return ip
        except:
            pass

        return "0.0.0.0"  # Все интерфейсы

    async def save_proxy_list(self, instances: List[ProxyInstance], backconnect_ip: str):
        """Сохраняет список прокси в файл"""
        proxy_list_file = self.work_dir / "proxy_list.txt"

        # Добавляем заголовок
        header = [
            "Наши контакты:",
            "Наш ТГ — https://t.me/nppr_team",
            "=" * 71,
            ""
        ]

        lines = header.copy()
        for instance in instances:
            lines.append(instance.get_proxy_string(backconnect_ip))

        async with aiofiles.open(proxy_list_file, 'w', encoding='utf-8') as f:
            await f.write('\n'.join(lines))

        logger.info(f"Список прокси сохранен в {proxy_list_file}")
        return proxy_list_file

    async def create_archive(self, proxy_list_file: Path) -> Tuple[Path, str]:
        """Создает защищенный архив со списком прокси"""
        archive_password = secrets.token_urlsafe(12)
        archive_file = self.work_dir / "proxy_archive.zip"

        # Создаем архив с паролем
        process = await asyncio.create_subprocess_exec(
            'zip', '-P', archive_password, str(archive_file), str(proxy_list_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.wait()

        logger.info(f"Архив создан: {archive_file}")
        return archive_file, archive_password

    async def upload_archive(self, archive_file: Path) -> Optional[str]:
        """Загружает архив на file.io"""
        logger.info("Загружаем архив на file.io...")
        return await FileUploader.upload_to_fileio(archive_file)

    def save_download_info(self, download_url: str, password: str, local_path: Path):
        """Сохраняет информацию о загрузке"""
        info_file = self.work_dir / "download_info.txt"

        info_lines = [
            f"Ссылка для скачивания: {download_url}",
            f"Пароль к архиву: {password}",
            f"Локальный файл: {local_path}",
            f"Дата создания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Наши контакты:",
            "Наш ТГ — https://t.me/nppr_team"
        ]

        with open(info_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(info_lines))

        logger.info(f"Информация о загрузке сохранена в {info_file}")

    def show_final_message(self, download_url: str, password: str, local_path: Path):
        """Отображает финальное сообщение"""
        message = f"""
{Colors.GREEN}##################################################
# Ваша ссылка на скачивание архива с прокси - {download_url}
# Пароль к архиву - {password}
# Файл с прокси можно найти по адресу - {local_path}
# Всегда ваш nppr_team!
# Наши контакты:
# Наш ТГ — https://t.me/nppr_team
##################################################{Colors.NC}
        """
        print(message)

    async def start_proxy_server(self):
        """Запускает прокси-сервер"""
        logger.info("Запускаем IPv6 прокси-сервер...")

        try:
            # Генерируем экземпляры прокси (без сохранения аутентификации при первом запуске)
            instances = await self.generate_proxy_instances(preserve_auth=False)
            self.current_instances = instances

            # ИСПРАВЛЕНИЕ: Сохраняем состояние сразу после генерации
            self.save_proxy_state(instances)

            # Добавляем IPv6 адреса
            await self.add_ipv6_addresses(instances)

            # Получаем IP для подключения
            backconnect_ip = self.get_backconnect_ip()

            # Запускаем 3proxy
            await self.proxy_manager.start_proxy_server(instances, backconnect_ip)

            # Сохраняем список прокси
            proxy_list_file = await self.save_proxy_list(instances, backconnect_ip)

            # Создаем архив
            archive_file, archive_password = await self.create_archive(proxy_list_file)

            # Загружаем архив
            download_url = await self.upload_archive(archive_file)

            if download_url:
                # Сохраняем информацию
                self.save_download_info(download_url, archive_password, proxy_list_file)

                # Отображаем результат
                self.show_final_message(download_url, archive_password, proxy_list_file)
            else:
                logger.warning("Не удалось загрузить архив, но прокси работают локально")
                print(f"Список прокси доступен в файле: {proxy_list_file}")

            logger.info(f"Прокси-сервер запущен! Доступно {len(instances)} прокси")
            logger.info(f"Порты: {self.config.start_port}-{self.config.start_port + len(instances) - 1}")

        except Exception as e:
            logger.error(f"Ошибка запуска прокси-сервера: {e}")
            await self.stop_proxy_server()
            raise

    async def stop_proxy_server(self):
        """Останавливает прокси-сервер"""
        logger.info("Останавливаем прокси-сервер...")

        await self.proxy_manager.stop_proxy_server()
        await self.remove_ipv6_addresses()
        self.current_instances.clear()

        logger.info("Прокси-сервер остановлен")

    async def restart_proxy_server(self):
        """Перезапускает прокси-сервер с сохранением аутентификации"""
        logger.info("Перезапускаем прокси-сервер...")
        await self.stop_proxy_server()

        # ИСПРАВЛЕНИЕ: При перезапуске сохраняем аутентификацию
        try:
            # Генерируем экземпляры прокси с сохранением аутентификации
            instances = await self.generate_proxy_instances(preserve_auth=True)
            self.current_instances = instances

            # Обновляем сохраненное состояние
            self.save_proxy_state(instances)

            # Добавляем IPv6 адреса
            await self.add_ipv6_addresses(instances)

            # Получаем IP для подключения
            backconnect_ip = self.get_backconnect_ip()

            # Запускаем 3proxy
            await self.proxy_manager.start_proxy_server(instances, backconnect_ip)

            # Сохраняем список прокси
            proxy_list_file = await self.save_proxy_list(instances, backconnect_ip)

            # Создаем архив
            archive_file, archive_password = await self.create_archive(proxy_list_file)

            # Загружаем архив
            download_url = await self.upload_archive(archive_file)

            if download_url:
                # Сохраняем информацию
                self.save_download_info(download_url, archive_password, proxy_list_file)

                # Отображаем результат
                self.show_final_message(download_url, archive_password, proxy_list_file)
            else:
                logger.warning("Не удалось загрузить архив, но прокси работают локально")
                print(f"Список прокси доступен в файле: {proxy_list_file}")

            logger.info(f"Прокси-сервер перезапущен! Доступно {len(instances)} прокси")
            logger.info(f"Порты: {self.config.start_port}-{self.config.start_port + len(instances) - 1}")

        except Exception as e:
            logger.error(f"Ошибка перезапуска прокси-сервера: {e}")
            await self.stop_proxy_server()
            raise

    async def rotate_ips(self):
        """ИСПРАВЛЕНИЕ: Ротация IP адресов с сохранением логинов/паролей и количества прокси"""
        logger.info("Выполняем ротацию IP адресов...")

        # Останавливаем текущий сервер
        await self.stop_proxy_server()

        try:
            # Генерируем новые экземпляры с сохранением аутентификации
            instances = await self.generate_proxy_instances(preserve_auth=True)
            self.current_instances = instances

            # Обновляем сохраненное состояние
            self.save_proxy_state(instances)

            # Добавляем новые IPv6 адреса
            await self.add_ipv6_addresses(instances)

            # Получаем IP для подключения
            backconnect_ip = self.get_backconnect_ip()

            # Запускаем 3proxy с новыми IP адресами
            await self.proxy_manager.start_proxy_server(instances, backconnect_ip)

            # Сохраняем обновленный список прокси
            proxy_list_file = await self.save_proxy_list(instances, backconnect_ip)

            # Создаем архив
            archive_file, archive_password = await self.create_archive(proxy_list_file)

            # Загружаем архив
            download_url = await self.upload_archive(archive_file)

            if download_url:
                # Сохраняем информацию
                self.save_download_info(download_url, archive_password, proxy_list_file)

                # Отображаем результат
                self.show_final_message(download_url, archive_password, proxy_list_file)

            logger.info(f"Ротация завершена! IP адреса обновлены, логины/пароли сохранены")
            logger.info(f"Количество прокси: {len(instances)} (сохранено)")
            logger.info(f"Порты: {self.config.start_port}-{self.config.start_port + len(instances) - 1}")

        except Exception as e:
            logger.error(f"Ошибка ротации IP адресов: {e}")
            await self.stop_proxy_server()
            raise

    async def get_status(self) -> Dict[str, Any]:
        """Получает статус прокси-сервера"""
        # Попытка загрузить сохраненное состояние для получения полной информации
        saved_state = ProxyState.load_from_file(self.state_file)

        return {
            "running": self.proxy_manager.is_running(),
            "proxy_count": len(self.current_instances) if self.current_instances else (
                len(saved_state.instances) if saved_state else 0),
            "config": {
                "parent_subnet": self.config.parent_subnet,
                "proxy_type": self.config.proxy_type.value,
                "auth_mode": self.config.auth_mode.value,
                "start_port": self.config.start_port,
                "interface": self.config.interface
            },
            "current_subnet": str(self.ipv6_manager.current_subnet) if self.ipv6_manager.current_subnet else None,
            "ipv6_addresses_count": len(self.current_ipv6_addresses),
            "state_file_exists": self.state_file.exists(),
            "last_update": saved_state.creation_date.isoformat() if saved_state else None
        }

    async def uninstall(self):
        """Полное удаление прокси-сервера"""
        logger.info("Удаляем прокси-сервер...")

        # Останавливаем сервер
        await self.stop_proxy_server()

        # Удаляем cron задачи
        await self.cron_manager.remove_cron_jobs()

        # Удаляем рабочую директорию
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir)

        logger.info("Прокси-сервер полностью удален")


class Colors:
    """ANSI цвета для терминала"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    NC = '\033[0m'  # No Color


class InteractiveSetup:
    """Интерактивная настройка прокси-сервера"""

    @staticmethod
    def show_header():
        """Отображает заголовок"""
        header = f"""
{Colors.RED} █████╗  ██████╗ ██████╗███████╗███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
███████║██║     ██║     █████╗  ███████╗███████╗
██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
██║  ██║╚██████╗╚██████╗███████╗███████║███████║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝{Colors.NC}

{Colors.GREEN}------------------------------------------------
IPv6 Proxy Server Manager v2.1.0 (ИСПРАВЛЕННАЯ ВЕРСИЯ)
ИСПРАВЛЕНИЯ:
• Сохранение логинов/паролей при ротации
• Правильная конфигурация HTTP прокси  
• Стабильное количество портов
Наши контакты:
Наш ТГ — https://t.me/nppr_team
------------------------------------------------{Colors.NC}
        """
        print(header)

    @staticmethod
    def get_user_input() -> ProxyConfig:
        """Получает настройки от пользователя"""
        InteractiveSetup.show_header()

        print(f"{Colors.CYAN}Настройка IPv6 прокси-сервера{Colors.NC}")
        print("=" * 40)

        # Родительская подсеть
        while True:
            parent_subnet = input(
                f"{Colors.YELLOW}Введите родительскую /48 подсеть (например: 2a0f:f702:19a): {Colors.NC}")
            if parent_subnet:
                try:
                    ipaddress.IPv6Network(f"{parent_subnet}::/48", strict=False)
                    break
                except:
                    print(f"{Colors.RED}Ошибка: неверный формат подсети!{Colors.NC}")
            else:
                print(f"{Colors.RED}Ошибка: подсеть обязательна!{Colors.NC}")

        # Количество прокси
        while True:
            try:
                proxy_count = input(f"{Colors.YELLOW}Количество прокси (по умолчанию 100): {Colors.NC}") or "100"
                proxy_count = int(proxy_count)
                if 1 <= proxy_count <= 50000:
                    break
                else:
                    print(f"{Colors.RED}Ошибка: количество должно быть от 1 до 50000!{Colors.NC}")
            except ValueError:
                print(f"{Colors.RED}Ошибка: введите число!{Colors.NC}")

        # Тип прокси
        print(f"{Colors.YELLOW}Тип прокси:{Colors.NC}")
        print("1) SOCKS5 (рекомендуется)")
        print("2) HTTP")
        while True:
            choice = input("Введите номер (1 или 2): ") or "1"
            if choice == "1":
                proxy_type = ProxyType.SOCKS5
                break
            elif choice == "2":
                proxy_type = ProxyType.HTTP
                break
            else:
                print(f"{Colors.RED}Ошибка: введите 1 или 2!{Colors.NC}")

        # Аутентификация
        print(f"{Colors.YELLOW}Режим аутентификации:{Colors.NC}")
        print("1) Без аутентификации")
        print("2) Единый логин/пароль")
        print("3) Случайные логин/пароль для каждого прокси (рекомендуется)")
        while True:
            choice = input("Введите номер (1-3): ") or "3"
            if choice == "1":
                auth_mode = AuthMode.NONE
                username = password = None
                break
            elif choice == "2":
                auth_mode = AuthMode.SINGLE
                username = input(f"{Colors.YELLOW}Введите логин: {Colors.NC}")
                password = input(f"{Colors.YELLOW}Введите пароль: {Colors.NC}")
                if not username or not password:
                    print(f"{Colors.RED}Ошибка: логин и пароль обязательны!{Colors.NC}")
                    continue
                break
            elif choice == "3":
                auth_mode = AuthMode.RANDOM
                username = password = None
                break
            else:
                print(f"{Colors.RED}Ошибка: введите 1, 2 или 3!{Colors.NC}")

        # Ротация
        while True:
            try:
                rotating_interval = input(
                    f"{Colors.YELLOW}Интервал ротации в минутах (0 - только ежедневно): {Colors.NC}") or "0"
                rotating_interval = int(rotating_interval)
                if rotating_interval >= 0:
                    break
                else:
                    print(f"{Colors.RED}Ошибка: интервал не может быть отрицательным!{Colors.NC}")
            except ValueError:
                print(f"{Colors.RED}Ошибка: введите число!{Colors.NC}")

        # Дополнительные настройки
        start_port = 30000
        advanced = input(f"{Colors.YELLOW}Изменить дополнительные настройки? (y/N): {Colors.NC}").lower()
        if advanced == 'y':
            while True:
                try:
                    start_port = input(f"{Colors.YELLOW}Начальный порт (по умолчанию 30000): {Colors.NC}") or "30000"
                    start_port = int(start_port)
                    if 1024 <= start_port <= 65536 - proxy_count:
                        break
                    else:
                        print(f"{Colors.RED}Ошибка: неверный диапазон портов!{Colors.NC}")
                except ValueError:
                    print(f"{Colors.RED}Ошибка: введите число!{Colors.NC}")

        return ProxyConfig(
            parent_subnet=parent_subnet,
            proxy_count=proxy_count,
            proxy_type=proxy_type,
            auth_mode=auth_mode,
            username=username,
            password=password,
            start_port=start_port,
            rotating_interval=rotating_interval
        )


async def main():
    """Основная функция"""
    import argparse

    parser = argparse.ArgumentParser(
        description="IPv6 Proxy Server Manager v2.1.0 - ИСПРАВЛЕННАЯ ВЕРСИЯ",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ИСПРАВЛЕНИЯ В ЭТОЙ ВЕРСИИ:
• При ротации сохраняются логины/пароли и количество прокси
• Исправлена конфигурация HTTP прокси (теперь 'proxy' вместо 'socks')
• Улучшена стабильность работы

Примеры использования:
  %(prog)s --interactive                    # Интерактивная настройка
  %(prog)s --parent-subnet "2a0f:f702:19a" --setup    # Настройка системы
  %(prog)s --parent-subnet "2a0f:f702:19a" --start    # Запуск сервера
  %(prog)s --parent-subnet "2a0f:f702:19a" --status   # Статус сервера
  %(prog)s --parent-subnet "2a0f:f702:19a" --stop     # Остановка сервера
  %(prog)s --parent-subnet "2a0f:f702:19a" --restart  # Перезапуск сервера
  %(prog)s --parent-subnet "2a0f:f702:19a" --rotate   # Ротация IP (сохраняет логины/пароли!)
  %(prog)s --parent-subnet "2a0f:f702:19a" --uninstall # Удаление

Продвинутые настройки:
  %(prog)s --parent-subnet "2a0f:f702:19a" \\
           --proxy-count 1000 \\
           --proxy-type http \\
           --auth-mode random \\
           --rotating-interval 30 \\
           --start

Контакты: https://t.me/nppr_team
        """
    )

    # Основные параметры
    parser.add_argument('--parent-subnet', help='Родительская /48 подсеть')
    parser.add_argument('--proxy-count', type=int, default=100, help='Количество прокси (по умолчанию: 100)')
    parser.add_argument('--proxy-type', choices=['http', 'socks5'], default='socks5',
                        help='Тип прокси (по умолчанию: socks5)')
    parser.add_argument('--auth-mode', choices=['none', 'single', 'random'], default='random',
                        help='Режим аутентификации (по умолчанию: random)')
    parser.add_argument('--username', help='Логин для режима single')
    parser.add_argument('--password', help='Пароль для режима single')
    parser.add_argument('--start-port', type=int, default=30000, help='Начальный порт (по умолчанию: 30000)')
    parser.add_argument('--rotating-interval', type=int, default=0, help='Интервал ротации в минутах (по умолчанию: 0)')
    parser.add_argument('--interface', default='eth0', help='Сетевой интерфейс (по умолчанию: eth0)')
    parser.add_argument('--localhost-only', action='store_true', help='Только localhost')
    parser.add_argument('--allowed-hosts', help='Разрешенные хосты (формат 3proxy)')
    parser.add_argument('--denied-hosts', help='Запрещенные хосты (формат 3proxy)')

    # Команды
    parser.add_argument('--interactive', action='store_true', help='Интерактивная настройка')
    parser.add_argument('--setup', action='store_true', help='Настройка системы')
    parser.add_argument('--start', action='store_true', help='Запуск прокси-сервера')
    parser.add_argument('--stop', action='store_true', help='Остановка прокси-сервера')
    parser.add_argument('--restart', action='store_true', help='Перезапуск прокси-сервера')
    parser.add_argument('--rotate', action='store_true', help='Ротация IP адресов (с сохранением логинов/паролей)')
    parser.add_argument('--status', action='store_true', help='Статус прокси-сервера')
    parser.add_argument('--uninstall', action='store_true', help='Удаление прокси-сервера')

    args = parser.parse_args()

    # Проверяем права root
    if os.geteuid() != 0:
        print(f"{Colors.RED}Ошибка: требуются права root (sudo){Colors.NC}")
        sys.exit(1)

    try:
        # Интерактивный режим
        if args.interactive:
            config = InteractiveSetup.get_user_input()
            manager = IPv6ProxyManager(config)

            print(f"\n{Colors.GREEN}Начинаем настройку...{Colors.NC}")
            await manager.setup_system()
            await manager.cron_manager.setup_cron_jobs(config)
            await manager.start_proxy_server()
            return

        # Проверяем наличие обязательных параметров
        if not args.parent_subnet:
            print(f"{Colors.RED}Ошибка: требуется --parent-subnet или --interactive{Colors.NC}")
            parser.print_help()
            sys.exit(1)

        # Создаем конфигурацию
        config = ProxyConfig(
            parent_subnet=args.parent_subnet,
            proxy_count=args.proxy_count,
            proxy_type=ProxyType(args.proxy_type),
            auth_mode=AuthMode(args.auth_mode),
            username=args.username,
            password=args.password,
            start_port=args.start_port,
            rotating_interval=args.rotating_interval,
            interface=args.interface,
            localhost_only=args.localhost_only,
            allowed_hosts=args.allowed_hosts,
            denied_hosts=args.denied_hosts
        )

        manager = IPv6ProxyManager(config)

        # Выполняем команды
        if args.setup:
            await manager.setup_system()
            await manager.cron_manager.setup_cron_jobs(config)
            print(f"{Colors.GREEN}Система настроена успешно!{Colors.NC}")

        elif args.start:
            await manager.start_proxy_server()

        elif args.stop:
            await manager.stop_proxy_server()

        elif args.restart:
            await manager.restart_proxy_server()

        elif args.rotate:
            print(f"{Colors.CYAN}Выполняем ротацию IP адресов с сохранением логинов/паролей...{Colors.NC}")
            await manager.rotate_ips()

        elif args.status:
            status = await manager.get_status()
            print(f"\n{Colors.CYAN}Статус прокси-сервера:{Colors.NC}")
            print(f"Запущен: {Colors.GREEN if status['running'] else Colors.RED}{status['running']}{Colors.NC}")
            print(f"Количество прокси: {status['proxy_count']}")
            print(f"Родительская подсеть: {status['config']['parent_subnet']}")
            print(f"Тип прокси: {status['config']['proxy_type']}")
            print(f"Режим аутентификации: {status['config']['auth_mode']}")
            print(
                f"Порты: {status['config']['start_port']}-{status['config']['start_port'] + status['proxy_count'] - 1}")
            if status['current_subnet']:
                print(f"Текущая подсеть: {status['current_subnet']}")
            print(f"IPv6 адресов: {status['ipv6_addresses_count']}")
            print(f"Файл состояния: {'✓' if status['state_file_exists'] else '✗'}")
            if status['last_update']:
                print(f"Последнее обновление: {status['last_update']}")

        elif args.uninstall:
            confirm = input(f"{Colors.YELLOW}Вы уверены, что хотите удалить прокси-сервер? (y/N): {Colors.NC}")
            if confirm.lower() == 'y':
                await manager.uninstall()
                print(f"{Colors.GREEN}Прокси-сервер успешно удален!{Colors.NC}")
            else:
                print("Отменено.")

        else:
            print(f"{Colors.YELLOW}Не указана команда. Используйте --help для справки.{Colors.NC}")
            parser.print_help()

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Операция прервана пользователем{Colors.NC}")
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        print(f"{Colors.RED}Ошибка: {e}{Colors.NC}")
        sys.exit(1)


if __name__ == "__main__":
    # Устанавливаем обработчик сигналов
    def signal_handler(signum, frame):
        print(f"\n{Colors.YELLOW}Получен сигнал {signum}, завершение работы...{Colors.NC}")
        sys.exit(0)


    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Запускаем основную функцию
    asyncio.run(main())