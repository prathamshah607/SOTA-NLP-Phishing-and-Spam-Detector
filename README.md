# SOTA-NLP-Phishing-and-Spam-Detector

Our Typosquat, IDN, and Combosquat detector analyzes domain names to check if they are impersonating brands.
 
It decodes domains for typos, profiles homoglyphs, checks for confusable characters, and calculates risk scores by edit-distance similarity to known brands and suspicious tokens.

For example here the misspelled URLs get high risk scores, while legitimate URLs get a low score.

_____

Our Natural Language phishing detector parses emails and messages using a RoBERTa model, outputting a phishing likelihood.

It also tracks the text for psychological tricks in addition to sentiment and emotion analysis.

For example, a fake Microsoft notice is flagged at a 95% phishing likelihood, while a routine Google calendar invite is rated safe at 0%.

By combining these signals into a multidimensional vector, our model hits an impressive 98% recall and 94% precision on benchmark phishing datasets like Enron, CEAS and Nazario.
