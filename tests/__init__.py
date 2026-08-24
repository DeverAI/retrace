"""ReTrace 回归测试套件。

运行：项目根目录执行  python -m unittest discover -s tests -v
原则：零第三方依赖；不触碰真实用户数据（DB/配置/Err.log 均重定向到临时目录）。
"""
import os
import tempfile

# 测试期间 Err.log 重定向到临时文件，避免污染仓库根的真实运行日志
from core import logger as _logger

_logger.ERR_LOG = os.path.join(tempfile.gettempdir(), "retrace_test_err.log")
try:
    if os.path.exists(_logger.ERR_LOG):
        os.remove(_logger.ERR_LOG)
except OSError:
    pass
