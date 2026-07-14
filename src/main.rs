use askama::Template;
use chrono::{DateTime, FixedOffset};
use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd, html};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};
use syntect::{highlighting::ThemeSet, html::highlighted_html_for_string, parsing::SyntaxSet};

const CONTENT_DIR: &str = "content";
const STATIC_DIR: &str = "static";
const PUBLIC_DIR: &str = "public";
const PUBLICATION_FILE: &str = "publications.toml";

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
If you are looking for a resume/CV (either you are a recruiter or ~what are you doing with your life?~), you can get one [here](https://github.com/alarmfox/curriculum-vitae/releases/latest/download/main.pdf).

## Site organization

Although I use this site for everything (I don't like fragmentation), maybe it is a good idea to keep the [research](/research) stuff away from [personal thoughts](/thoughts).
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

#[derive(Debug, Deserialize)]
struct Publication {
    title: String,
    authors: Vec<String>,
    status: String,

    #[serde(rename = "abstract")]
    abstract_text: String,

    pdf: String,
    post: Option<String>,
    year: u32,
}

impl Publication {
    fn authors_string(&self) -> String {
        self.authors.join(", ")
    }

    fn short_abstract(&self) -> String {
        const MAX_WORDS: usize = 50;

        let words: Vec<&str> = self.abstract_text.split_whitespace().collect();

        if words.len() <= MAX_WORDS {
            self.abstract_text.clone()
        } else {
            format!("{}…", words[..MAX_WORDS].join(" "))
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

    latest_posts: &'a [PostSummary],
    publications: &'a [Publication],
}

#[derive(Template)]
#[template(path = "section.html")]
struct SectionIndexTemplate<'a> {
    first_name: String,
    section_name: String,
    posts: &'a [Post],
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
    println!("processing: {}", path.display());
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

fn load_section(path: &Path) -> io::Result<Vec<Post>> {
    let mut posts = std::fs::read_dir(path)?
        .filter_map(|entry| match entry {
            Ok(entry) => {
                let path = entry.path();

                if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
                    Some(build_post(&path))
                } else {
                    None
                }
            }
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, io::Error>>()?;

    posts.sort_by(|a, b| b.meta.date.cmp(&a.meta.date));

    Ok(posts)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("content directory at {}", CONTENT_DIR);
    println!("static directory at {}", STATIC_DIR);
    println!("public directory at {}", PUBLIC_DIR);

    let opath = Path::new(PUBLIC_DIR);
    let content_path = Path::new(CONTENT_DIR);

    setup_public_directory(opath)?;

    let section_names = ["research", "thoughts"];
    let mut all_posts = Vec::new();

    for section_name in section_names {
        let section_content_path = content_path.join(section_name);
        let section_output_path = opath.join(section_name);

        let posts = load_section(&section_content_path)?;

        std::fs::create_dir_all(&section_output_path)?;

        let template = SectionIndexTemplate {
            first_name: FIRST_NAME.to_string(),
            section_name: section_name.to_string(),
            posts: &posts,
        };

        let html = template.render()?;

        std::fs::write(section_output_path.join("index.html"), html)?;

        for post in &posts {
            let html = post.template.render()?;

            let relative = post.template.relative_path.trim_end_matches(".md");

            let output_dir = opath.join(relative);

            std::fs::create_dir_all(&output_dir)?;
            std::fs::write(output_dir.join("index.html"), html)?;
        }

        all_posts.extend(posts);
    }

    for post in all_posts.iter() {
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
    all_posts.sort_by(|a, b| b.meta.date.cmp(&a.meta.date));
    let latest_posts: Vec<PostSummary> = all_posts
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

    /* Build publication array */
    let publications_content = std::fs::read_to_string(content_path.join(PUBLICATION_FILE))?;

    let mut publications: HashMap<String, Vec<Publication>> =
        toml::from_str(&publications_content)?;

    let mut publications = publications.remove("publication").unwrap_or(Vec::new());

    publications.sort_by(|a, b| b.year.cmp(&a.year));

    /* Finally build index.html */
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
        latest_posts: &latest_posts,
        publications: &publications,
    };

    let html = index.render()?;
    let mut file = std::fs::File::create(opath.join("index.html"))?;
    file.write_all(html.as_bytes())?;

    Ok(())
}
