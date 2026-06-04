"""Unit tests for the reflection / dynamic-code-loading / RCE-from-extras patterns."""
from __future__ import annotations

import re

from clawditor.scan.code_patterns import PATTERNS


def _match(pat_name: str, text: str) -> bool:
    return re.search(PATTERNS[pat_name], text) is not None


# ----- dex_class_loader_from_extra -----
# Pattern: \bnew\s+DexClassLoader\s*\([^)]*getStringExtra
# Note: the [^)]* class can't cross a ')', so a wrapped expression like
# `getIntent().getStringExtra("x")` between `(` and the extra-call defeats the regex.
# Real decompiled jadx output usually binds the Intent to a local first, so the
# pattern still catches the common case.

def test_dex_class_loader_from_extra_positive_basic():
    src = 'new DexClassLoader(intent.getStringExtra("path"), opt, null, parent)'
    assert _match("dex_class_loader_from_extra", src)


def test_dex_class_loader_from_extra_positive_spacing():
    src = 'new  DexClassLoader ( intent.getStringExtra("k"), o, n, p)'
    assert _match("dex_class_loader_from_extra", src)


def test_dex_class_loader_from_extra_positive_assigned():
    src = 'DexClassLoader cl = new DexClassLoader(i.getStringExtra("x"), null, null, ldr);'
    assert _match("dex_class_loader_from_extra", src)


def test_dex_class_loader_from_extra_negative_constant_path():
    src = 'new DexClassLoader("/data/local/cache.dex", null, null, parent)'
    assert not _match("dex_class_loader_from_extra", src)


def test_dex_class_loader_from_extra_negative_files_dir():
    src = 'new DexClassLoader(getFilesDir().getPath(), null, null, parent)'
    assert not _match("dex_class_loader_from_extra", src)


def test_dex_class_loader_from_extra_negative_variable():
    # Extra read happens before, but the DexClassLoader call only sees a local.
    # Static pattern can't link these — and shouldn't false-positive on the call alone.
    src = 'String s = intent.getStringExtra("x"); new DexClassLoader(s, null, null, ldr);'
    assert not _match("dex_class_loader_from_extra", src)


# ----- runtime_exec_from_extra -----
# Pattern: Runtime\.getRuntime\(\)\.exec\s*\([^)]*get(?:String|Bundle)Extra

def test_runtime_exec_from_extra_positive_basic():
    src = 'Runtime.getRuntime().exec(intent.getStringExtra("cmd"))'
    assert _match("runtime_exec_from_extra", src)


def test_runtime_exec_from_extra_positive_spacing():
    src = 'Runtime.getRuntime().exec ( bundle.getStringExtra("command") )'
    assert _match("runtime_exec_from_extra", src)


def test_runtime_exec_from_extra_positive_bundle_extra():
    src = 'Process p = Runtime.getRuntime().exec(intent.getBundleExtra("a").toString());'
    assert _match("runtime_exec_from_extra", src)


def test_runtime_exec_from_extra_negative_constant():
    src = 'Runtime.getRuntime().exec("/system/bin/ls")'
    assert not _match("runtime_exec_from_extra", src)


def test_runtime_exec_from_extra_negative_array_constant():
    src = 'Runtime.getRuntime().exec(new String[]{"ls", "-la"})'
    assert not _match("runtime_exec_from_extra", src)


def test_runtime_exec_from_extra_negative_local_variable():
    # Extra read in earlier statement — static regex correctly doesn't link them.
    src = 'String s = intent.getStringExtra("y"); Runtime.getRuntime().exec(s);'
    assert not _match("runtime_exec_from_extra", src)


# ----- sharedprefs_world_writeable -----
# Pattern: MODE_WORLD_WRITEABLE\b

def test_sharedprefs_world_writeable_positive_getsharedprefs():
    src = 'getSharedPreferences("x", MODE_WORLD_WRITEABLE)'
    assert _match("sharedprefs_world_writeable", src)


def test_sharedprefs_world_writeable_positive_context_qualified():
    src = 'ctx.openFileOutput("f", Context.MODE_WORLD_WRITEABLE)'
    assert _match("sharedprefs_world_writeable", src)


def test_sharedprefs_world_writeable_positive_or_combined():
    src = 'int flags = MODE_WORLD_WRITEABLE | MODE_APPEND;'
    assert _match("sharedprefs_world_writeable", src)


def test_sharedprefs_world_writeable_negative_private():
    src = 'getSharedPreferences("x", MODE_PRIVATE)'
    assert not _match("sharedprefs_world_writeable", src)


def test_sharedprefs_world_writeable_negative_readable_only():
    src = 'getSharedPreferences("x", MODE_WORLD_READABLE)'
    assert not _match("sharedprefs_world_writeable", src)


def test_sharedprefs_world_writeable_negative_suffix_identifier():
    # \b ensures we don't match a longer identifier like MODE_WORLD_WRITEABLEISH
    src = 'int x = MODE_WORLD_WRITEABLEISH;'
    assert not _match("sharedprefs_world_writeable", src)


# ----- class_forname_from_extra -----
# Pattern: \bClass\.forName\s*\([^)]*get(?:String|Char|Bundle)Extra

def test_class_forname_from_extra_positive_basic():
    src = 'Class.forName(intent.getStringExtra("clz"))'
    assert _match("class_forname_from_extra", src)


def test_class_forname_from_extra_positive_spacing():
    src = 'Class.forName ( bundle.getStringExtra("x") )'
    assert _match("class_forname_from_extra", src)


def test_class_forname_from_extra_positive_bundle_extra():
    src = 'Class c = Class.forName(i.getBundleExtra("a").getString("y"));'
    # The Bundle case: forName(... getBundleExtra ...) matches because
    # getBundleExtra is in (String|Char|Bundle)Extra union.
    assert _match("class_forname_from_extra", src)


def test_class_forname_from_extra_negative_constant():
    src = 'Class.forName("java.lang.String")'
    assert not _match("class_forname_from_extra", src)


def test_class_forname_from_extra_negative_variable():
    src = 'String s = intent.getStringExtra("y"); Class.forName(s);'
    assert not _match("class_forname_from_extra", src)


def test_class_forname_from_extra_negative_constant_field():
    src = 'Class c = Class.forName(CLASS_NAME);'
    assert not _match("class_forname_from_extra", src)
