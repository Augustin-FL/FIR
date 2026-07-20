// Patch handlebars: Convert ${...} to {{...}}
// Then use compileAST from https://github.com/elastic/handlebars
// To allow handlebars usage when having a strict CSP
const originalCompile = Handlebars.compile;

Handlebars.compile = function (templateStr, options) {
  const converted = templateStr.replace(/\$\{([^}]+)\}/g, "{{$1}}");
  if (typeof Handlebars.compileAST === "function") {
    return Handlebars.compileAST(converted, options);
  }

  return originalCompile.call(this, converted, options);
};
