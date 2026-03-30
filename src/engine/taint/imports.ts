/**
 * Import collection for taint tracking.
 * Collects all imports/requires at the file level across supported languages.
 */
import type { AstLanguage } from '../../checks/types.js';
import type { SyntaxNode } from '../ast-helpers.js';
import { walkTree } from '../ast-helpers.js';

/**
 * Collect all imports/requires at the file level.
 * Returns a map of localName -> moduleName.
 * Language-aware: handles import statements for JS/TS, Python, Go, Ruby, PHP.
 */
export function collectImports(rootNode: SyntaxNode, language?: AstLanguage): Map<string, string> {
  const imports = new Map<string, string>();

  walkTree(rootNode, (node) => {
    // ES import: import X from 'mod' / import { X } from 'mod'
    if (node.type === 'import_statement') {
      const source = node.childForFieldName('source');
      if (!source) return;
      // strip quotes
      const moduleName = source.text.replace(/['"]/g, '');

      // Check for default import
      // import_clause can contain: identifier (default), named_imports, namespace_import
      walkTree(node, (child) => {
        if (child.type === 'identifier' && child.parent?.type === 'import_clause') {
          imports.set(child.text, moduleName);
        }
        if (child.type === 'import_specifier') {
          const name = child.childForFieldName('name');
          const alias = child.childForFieldName('alias');
          const localName = alias ? alias.text : name?.text;
          if (localName) imports.set(localName, moduleName);
        }
        if (child.type === 'namespace_import') {
          // import * as X from 'mod'
          const nameNode = child.childForFieldName('name');
          if (nameNode) imports.set(nameNode.text, moduleName);
        }
      });
    }

    // CommonJS require: const X = require('mod') / const { X } = require('mod')
    if (node.type === 'variable_declarator') {
      const init = node.childForFieldName('value') ?? node.childForFieldName('init');
      if (!init) return;

      // Check if init is a require call
      let requireModule: string | null = null;
      if (init.type === 'call_expression') {
        const fn = init.childForFieldName('function');
        if (fn && fn.text === 'require') {
          const args = init.childForFieldName('arguments');
          if (args && args.childCount > 0) {
            // First named child is the argument
            for (let i = 0; i < args.childCount; i++) {
              const arg = args.child(i);
              if (arg && arg.isNamed) {
                requireModule = arg.text.replace(/['"]/g, '');
                break;
              }
            }
          }
        }
      }
      if (!requireModule) return;

      const nameNode = node.childForFieldName('name');
      if (!nameNode) return;

      if (nameNode.type === 'identifier') {
        // const fs = require('fs')
        imports.set(nameNode.text, requireModule);
      } else if (nameNode.type === 'object_pattern') {
        // const { exec } = require('child_process')
        walkTree(nameNode, (child) => {
          if (child.type === 'shorthand_property_identifier_pattern') {
            imports.set(child.text, requireModule!);
          } else if (child.type === 'pair_pattern') {
            const key = child.childForFieldName('key');
            const val = child.childForFieldName('value');
            if (val && val.type === 'identifier') {
              imports.set(val.text, requireModule!);
            } else if (key && key.type === 'identifier') {
              imports.set(key.text, requireModule!);
            }
          }
        });
      }
    }
  });

  // Python: from X import Y, import X
  if (language === 'python') {
    walkTree(rootNode, (node) => {
      if (node.type === 'import_from_statement') {
        const moduleNode = node.childForFieldName('module_name');
        if (!moduleNode) return;
        const moduleName = moduleNode.text;
        // Collect imported names
        walkTree(node, (child) => {
          if (child.type === 'dotted_name' && child !== moduleNode) {
            imports.set(child.text, moduleName);
          }
          if (child.type === 'aliased_import') {
            const alias = child.childForFieldName('alias');
            const name = child.childForFieldName('name');
            if (alias) imports.set(alias.text, moduleName);
            else if (name) imports.set(name.text, moduleName);
          }
        });
      }
      if (node.type === 'import_statement') {
        walkTree(node, (child) => {
          if (child.type === 'dotted_name' && child.parent === node) {
            imports.set(child.text, child.text);
          }
        });
      }
    });
  }

  // Go: import "pkg" or import ( "pkg" )
  if (language === 'go') {
    walkTree(rootNode, (node) => {
      if (node.type === 'import_spec') {
        const path = node.childForFieldName('path');
        if (!path) return;
        const pkgPath = path.text.replace(/"/g, '');
        const alias = node.childForFieldName('name');
        if (alias) {
          imports.set(alias.text, pkgPath);
        } else {
          // Use last segment of import path as the local name
          const segments = pkgPath.split('/');
          imports.set(segments[segments.length - 1], pkgPath);
        }
      }
    });
  }

  // Ruby: require 'gem_name'
  if (language === 'ruby') {
    walkTree(rootNode, (node) => {
      if (node.type === 'call') {
        const method = node.childForFieldName('method');
        if (method && (method.text === 'require' || method.text === 'require_relative')) {
          const args = node.childForFieldName('arguments');
          if (args) {
            for (let i = 0; i < args.childCount; i++) {
              const child = args.child(i);
              if (child && child.type === 'string') {
                const modName = child.text.replace(/['"]/g, '');
                imports.set(modName, modName);
              }
            }
          }
        }
      }
    });
  }

  // PHP: use statements and require/include
  if (language === 'php') {
    walkTree(rootNode, (node) => {
      if (node.type === 'namespace_use_declaration') {
        walkTree(node, (child) => {
          if (child.type === 'namespace_use_clause') {
            const name = child.childForFieldName('name');
            if (name) {
              const parts = name.text.split('\\');
              imports.set(parts[parts.length - 1], name.text);
            }
          }
        });
      }
    });
  }

  return imports;
}
