#!/usr/bin/env python3
"""Generate credential-free Apple Shortcuts templates; sign with macOS shortcuts CLI."""
from pathlib import Path
import plistlib
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'Shortcuts' / 'source'

def make_shortcut(name, command, color):
    text_id = str(uuid.uuid4()).upper()
    return {
        'WFWorkflowName': name,
        'WFWorkflowClientVersion': '2605.0.5',
        'WFWorkflowMinimumClientVersion': 900,
        'WFWorkflowMinimumClientVersionString': '900',
        'WFWorkflowIcon': {'WFWorkflowIconStartColor': color, 'WFWorkflowIconGlyphNumber': 61440},
        'WFWorkflowTypes': [],
        'WFWorkflowInputContentItemClasses': [],
        'WFWorkflowOutputContentItemClasses': [],
        'WFWorkflowHasShortcutInputVariables': False,
        'WFWorkflowImportQuestions': [
            {'ActionIndex': 1, 'Category': 'Parameter', 'ParameterKey': 'WFURL',
             'Text': '粘贴旧手机蓝牙灯 App 提供的“请求地址”（两个快捷指令使用同一地址）',
             'DefaultValue': ''},
            {'ActionIndex': 0, 'Category': 'Parameter', 'ParameterKey': 'WFTextActionText',
             'Text': f'粘贴旧手机提供的“{command}内容”，请完整复制，不要添加空格或换行',
             'DefaultValue': ''},
        ],
        'WFWorkflowActions': [
            {'WFWorkflowActionIdentifier': 'is.workflow.actions.gettext',
             'WFWorkflowActionParameters': {'WFTextActionText': '', 'UUID': text_id}},
            {'WFWorkflowActionIdentifier': 'is.workflow.actions.downloadurl',
             'WFWorkflowActionParameters': {
                 'WFURL': '', 'WFHTTPMethod': 'POST', 'WFHTTPBodyType': 'File',
                 'WFRequestVariable': {'Value': {'OutputUUID': text_id, 'Type': 'ActionOutput', 'OutputName': '文本'},
                                       'WFSerializationType': 'WFTextTokenAttachment'},
                 'UUID': str(uuid.uuid4()).upper(),
             }},
        ],
    }

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, command, color in [('回家开灯', '开灯', 4282601983), ('离家关灯', '关灯', 4251333119)]:
        shortcut = make_shortcut(name, command, color)
        assert len(shortcut['WFWorkflowActions']) == 2
        for question in shortcut['WFWorkflowImportQuestions']:
            params = shortcut['WFWorkflowActions'][question['ActionIndex']]['WFWorkflowActionParameters']
            assert question['ParameterKey'] in params
            assert params[question['ParameterKey']] == ''
        params = shortcut['WFWorkflowActions'][1]['WFWorkflowActionParameters']
        assert params['WFRequestVariable']['Value']['OutputUUID'] == shortcut['WFWorkflowActions'][0]['WFWorkflowActionParameters']['UUID']
        path = OUTPUT / (name + '.shortcut')
        with path.open('wb') as output:
            plistlib.dump(shortcut, output, fmt=plistlib.FMT_BINARY)
        print(f'Created credential-free template: {path.name}')

if __name__ == '__main__':
    main()
