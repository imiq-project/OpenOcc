import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';
import { providePrimeNG } from 'primeng/config';
import Aura from '@primeng/themes/lara'
import { Routes } from '@angular/router';
import { MessageService } from 'primeng/api';

const routes: Routes = [];

export const appConfig: ApplicationConfig = {
    providers: [
        provideBrowserGlobalErrorListeners(),
        provideRouter(routes),
        providePrimeNG({
            theme: {
                preset: Aura
            }
        }),
        MessageService,
    ]
};
