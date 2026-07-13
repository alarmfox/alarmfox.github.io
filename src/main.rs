use askama::Template;
use chrono::{DateTime, FixedOffset};
use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd, html};
use serde::Deserialize;
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use syntect::{highlighting::ThemeSet, html::highlighted_html_for_string, parsing::SyntaxSet};

const CONTENT_DIR: &str = "content";
const STATIC_DIR: &str = "static";
const PUBLIC_DIR: &str = "public";

/* Personal data */
const USERNAME: &str = "alarmfox";
const FULL_NAME: &str = "giuseppe capasso";
const FIRST_NAME: &str = "giuseppe";
const EMAILS: [&str; 1] = ["capassog97@gmail.com"];
const GITHUB: &str = "https://github.com/alarmfox";
const CODEBERG: &str = "https://codeberg.org/alarmfox";
const DESCRIPTION: &str = r"
This is my space where I write about my interests and thoughts which include (and are not limited to):

- Computer Systems: I am deeply interested in high-performance systems, software security, networking and all the OS/low-level stuff.
- Entertainment (books, videogames, music, film)
- Real world stuff

There is not a specific target for this website. Sometimes, one just needs a place to share thoughts and put ideas together.
If you are looking for a resume/CV (either you are a recruiter or ~what are you doing with your life?~), you can get one [**here**](https://github.com/alarmfox/curriculum-vitae/releases/latest/download/main.pdf).

## Site organization

Although I use this site for everything (I don't like fragmentation), maybe it is a good idea to keep the [**research**](/research) stuff away from [**personal thoughts**](/thoughts).
";

static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
static THEME_SET: OnceLock<ThemeSet> = OnceLock::new();

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

/* Create a public directory. It will be like this:
 *
 * /index.html
 * /static
 * /thoughts
 * /research
 */
fn setup_public_directory(path: &Path) -> io::Result<()> {
    if let Err(e) = std::fs::remove_dir_all(PUBLIC_DIR) {
        if !matches!(e.kind(), std::io::ErrorKind::NotFound) {
            return Err(e);
        }
    }

    const DIRS: [&str; 3] = ["static", "thoughts", "research"];
    for dir in DIRS {
        std::fs::create_dir_all(path.join(dir))?;
    }

    /* Populate static directory */
    copy_dir_all(Path::new(STATIC_DIR), path.join("static"))?;

    Ok(())
}

#[derive(Debug, Clone)]
struct Post {
    template: PostTemplate,
    meta: PostMetadata,
}

#[derive(Template, Clone, Debug)]
#[template(path = "post.html")]
struct PostTemplate {
    title: String,
    body: String,
    first_name: String,
    relative_path: String,
    date: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PostMetadata {
    title: String,
    date: DateTime<FixedOffset>,
}

#[derive(Debug)]
struct PostSummary {
    title: String,
    relative_path: String,
    date: String,
}
impl PostSummary {
    pub fn short_title(&self) -> String {
        const MAX: usize = 50;

        if self.title.chars().count() <= MAX {
            self.title.clone()
        } else {
            format!("{}…", self.title.chars().take(MAX - 1).collect::<String>())
        }
    }
}

#[derive(Template)]
#[template(path = "index.html")]
struct Index<'a> {
    full_name: &'a str,
    first_name: &'a str,
    username: &'a str,
    description: &'a str,
    email: &'a str,
    github: &'a str,
    codeberg: &'a str,

    latest_posts: Vec<PostSummary>,
}

fn split_front_matter(contents: &str) -> Option<(&str, &str)> {
    let rest = contents.strip_prefix("+++\n")?;

    let (front, body) = rest.split_once("\n+++\n")?;

    Some((front, body))
}

fn markdown_to_html(markdown: &str) -> io::Result<String> {
    let syntax_set = SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines);

    let theme_set = THEME_SET.get_or_init(ThemeSet::load_defaults);

    let theme = &theme_set.themes["base16-ocean.dark"];

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);

    let mut parser = Parser::new_ext(markdown, options);
    let mut events = Vec::new();

    while let Some(event) = parser.next() {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let language = match kind {
                    CodeBlockKind::Fenced(language) => {
                        // Handles fences such as ```rust or ```rust linenos
                        language.split_whitespace().next().unwrap_or("").to_owned()
                    }
                    CodeBlockKind::Indented => String::new(),
                };

                let mut code = String::new();

                for code_event in parser.by_ref() {
                    match code_event {
                        Event::Text(text) | Event::Code(text) => {
                            code.push_str(&text);
                        }

                        Event::SoftBreak | Event::HardBreak => {
                            code.push('\n');
                        }

                        Event::End(TagEnd::CodeBlock) => {
                            break;
                        }

                        _ => {}
                    }
                }

                let syntax = if language.is_empty() {
                    syntax_set.find_syntax_plain_text()
                } else {
                    syntax_set
                        .find_syntax_by_token(&language)
                        .unwrap_or_else(|| syntax_set.find_syntax_plain_text())
                };

                let highlighted = highlighted_html_for_string(&code, syntax_set, syntax, theme)
                    .map_err(io::Error::other)?;

                events.push(Event::Html(CowStr::Boxed(highlighted.into_boxed_str())));
            }

            other => events.push(other),
        }
    }

    let mut output = String::new();
    html::push_html(&mut output, events.into_iter());

    Ok(output)
}

fn build_post(path: &Path) -> io::Result<Post> {
    let mut content = String::new();

    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);

    let mut file = std::fs::File::open(path)?;
    file.read_to_string(&mut content)?;

    let (header, body) = split_front_matter(&content).expect("bad formatted file");

    /* Header */
    let meta: PostMetadata = toml::from_str(header).expect("header error");

    /* Render the post header */
    let rendered = markdown_to_html(body)?;

    let relative_path = PathBuf::from(path.strip_prefix(CONTENT_DIR).expect("invalid error"))
        .to_string_lossy()
        .into();

    Ok(Post {
        meta: PostMetadata {
            title: meta.title.clone(),
            date: meta.date,
        },
        template: PostTemplate {
            first_name: FIRST_NAME.to_string(),
            title: meta.title,
            body: rendered,
            date: meta.date.format("%B %-d, %Y").to_string(),
            relative_path,
        },
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("content directory at {}", CONTENT_DIR);
    println!("static directory at {}", STATIC_DIR);
    println!("public directory at {}", PUBLIC_DIR);
    let opath = Path::new(PUBLIC_DIR);
    let content_path = Path::new(CONTENT_DIR);

    setup_public_directory(opath)?;

    let blog_sections = [content_path.join("research"), content_path.join("thoughts")];
    let mut posts = Vec::new();

    for blog_section in blog_sections {
        println!("exploring {}", blog_section.display());
        posts.extend(
            std::fs::read_dir(blog_section)?
                .map(|e| {
                    let path = e?.path();
                    build_post(&path)
                })
                .collect::<Result<Vec<_>, io::Error>>()?,
        );
    }

    for post in posts.iter() {
        let mut path = opath.join(&post.template.relative_path);
        path.set_extension("html");

        let html = post.template.render()?;
        std::fs::write(path, html)?;
    }

    /* Create index.html:
     *
     * 1. Create recent posts: top 20 recent posts
     * 2. Create description
     * 3. Render html to index.html
     */

    posts.sort_by(|a, b| b.meta.date.cmp(&a.meta.date));
    let latest_posts: Vec<PostSummary> = posts
        .iter()
        .take(20)
        .map(|p| {
            let mut relative_path = PathBuf::from(p.template.relative_path.clone());
            relative_path.set_extension("html");
            PostSummary {
                title: p.meta.title.clone(),
                relative_path: relative_path.to_string_lossy().into(),
                date: p.meta.date.format("%Y-%m-%d").to_string(),
            }
        })
        .collect();

    let mut description = String::new();
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = pulldown_cmark::Parser::new_ext(DESCRIPTION, options);
    pulldown_cmark::html::push_html(&mut description, parser);

    let index = Index {
        first_name: FIRST_NAME,
        full_name: FULL_NAME,
        username: USERNAME,
        description: &description,
        email: EMAILS[0],
        github: GITHUB,
        codeberg: CODEBERG,
        latest_posts,
    };

    let html = index.render()?;
    let mut file = std::fs::File::create(opath.join("index.html"))?;
    file.write_all(html.as_bytes())?;

    Ok(())
}
