"""GUI 页面包：每页一文件，MainWindow 经 build_pages() 按模块开关装配。"""
from ui.pages.ai_pages import AiHelperPage, AiPage
from ui.pages.browser import BrowserPage
from ui.pages.decompile_page import DecompilePage
from ui.pages.embed import EmbedPage
from ui.pages.evolve import EvolvePage
from ui.pages.hunt import HuntPage
from ui.pages.overview import OverviewPage
from ui.pages.pcap import PcapPage
from ui.pages.privacy import PrivacyGuardPage
from ui.pages.regscan import RegscanPage
from ui.pages.screener import ScreenerPage
from ui.pages.settings import SettingsPage
from ui.pages.tracking import TrackingPage
from ui.pages.watcher import WatcherPage


def build_pages(win):
    """按 config 模块开关生成 (标签, 页面实例) 列表；关闭的模块不出现入口。"""
    from core import config
    pages = [("总览", OverviewPage(win))]
    if config.enabled("tracking"):
        pages.append(("追踪任务", TrackingPage(win)))
    if config.enabled("privacy_guard"):
        pages.append(("隐私保护", PrivacyGuardPage(win)))
    if config.enabled("screener"):
        pages.append(("筛查工作台", ScreenerPage(win)))
    if config.enabled("agent"):
        pages.append(("AI 助手", AiHelperPage(win)))
    if config.enabled("pcap"):
        pages.append(("M1 抓包", PcapPage(win)))
    if config.enabled("regscan"):
        pages.append(("M2 注册表", RegscanPage(win)))
    if config.enabled("embedding"):
        pages.append(("M3 经验检索", EmbedPage(win)))
    if config.enabled("decompile"):
        pages.append(("M6 反编译", DecompilePage(win)))
    if config.enabled("watcher"):
        pages.append(("M7 观察", WatcherPage(win)))
    if config.enabled("browser"):
        pages.append(("M4 浏览器", BrowserPage(win)))
    if config.enabled("ai"):
        pages.append(("M8 大模型", AiPage(win)))
    if config.enabled("evolve"):
        pages.append(("M5 进化", EvolvePage(win)))
    if config.enabled("hunt"):
        pages.append(("M9 主流程", HuntPage(win)))
    pages.append(("设置", SettingsPage(win)))
    return pages
