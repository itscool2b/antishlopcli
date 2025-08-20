# shell.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.nodejs_20
  ];

  shellHook = ''
    echo "✅ Claude Dev Shell Ready!"
    echo "💡 Run Claude Code with:"
    echo "    npx @anthropic-ai/claude-code"
  '';
}
