import { Directive, TemplateRef } from '@angular/core';

@Directive({
    selector: '[leafletPopup]'
})
export class PopupDirective {
    constructor(public template: TemplateRef<any>) { }
}
