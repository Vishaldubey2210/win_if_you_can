import pytest
from slopguard.extraction.javascript import JavaScriptExtractor
from slopguard.core.models import Ecosystem

def test_extract_es_modules_and_cjs():
    code = """
// Import comments should be ignored
// import ignored from 'ignored';
import React, { useState } from 'react';
import * as _ from 'lodash/debounce';
import '@angular/core/testing';
const express = require("express");
const fs = require('fs');
const path = require('node:path');
import('./dynamic-module');
import '../components/Button';
/* Multi-line comment
import commented from 'commented';
*/
"""
    extractor = JavaScriptExtractor()
    deps = extractor.extract(code)

    names = {d.name: d for d in deps}

    # Verify standard Node built-ins
    assert "fs" in names
    assert names["fs"].is_stdlib is True
    assert "path" in names
    assert names["path"].is_stdlib is True

    # Verify third party packages
    assert "react" in names
    assert names["react"].is_stdlib is False

    # Verify subpath cleaned to root package
    assert "lodash" in names
    assert names["lodash"].is_stdlib is False

    # Verify scoped package preserved
    assert "@angular/core" in names
    assert names["@angular/core"].is_stdlib is False

    assert "express" in names

    # Verify relative imports flagged
    rel_deps = [d for d in deps if d.is_relative]
    assert any("./dynamic-module" in d.name for d in rel_deps)
    assert any("../components/Button" in d.name for d in rel_deps)

    # Verify commented out imports are NOT extracted
    assert "ignored" not in names
    assert "commented" not in names
