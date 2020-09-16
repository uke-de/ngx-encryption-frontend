import { NgModule } from '@angular/core';
// @ts-ignore
import messages from "./messages.json";


@NgModule({})
export abstract class LocalizationModule {

  /**
   * Extracts the key:value pairs for the given locale from messages.json
   * @param locale
   * @param fallback
   */
  static initTranslations(locale?: string, fallback = 'en'):Record<string, string> {
    let shortlocale = locale?.replace(/-.*/,'');

    let translation: Record<string, string> = {};
    for (let msg in messages) {
      translation[msg] = messages[msg][locale] || messages[msg][shortlocale] || messages[msg][fallback] || msg;
    }

    return translation;
  }

}
